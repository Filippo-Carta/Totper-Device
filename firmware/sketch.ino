#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <Preferences.h>
#include <mbedtls/md.h>
#include <vector>

const int BUTTON_CYCLE   = 5;
const int BUTTON_CONFIRM = 6;

const uint64_t TOTP_STEP   = 30;
const int      TOTP_DIGITS = 6;

const int   MAX_FAIL    = 5;
const char* DEFAULT_PIN = "00000";

Preferences prefs;

static uint64_t baseUnix   = 0;
static uint32_t baseMillis = 0;
static bool     timeSynced = false;

uint64_t currentTime() {
  if (!timeSynced) return 0;
  return baseUnix + (millis() - baseMillis) / 1000UL;
}

struct TOTPAccount { String name; String base32Secret; };
std::vector<TOTPAccount>           accounts;
std::vector<std::vector<uint8_t>>  secretKeys;
int  currentAccount = 0;
bool Locked         = true;
char currentPIN[6]  = {};

int base32CharValue(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= '2' && c <= '7') return 26 + (c - '2');
  return -1;
}

bool isFirstBoot() {
  prefs.begin("totp", true);
  bool exists = prefs.isKey("pin");
  prefs.end();
  return !exists;
}

std::vector<uint8_t> base32Decode(const char* b32) {
  std::vector<uint8_t> out;
  int buf = 0, bits = 0;
  for (const char* p = b32; *p; p++) {
    char c = *p;
    if (c == '=' || c == ' ' || c == '\n' || c == '\r' || c == '-') continue;
    if (c >= 'a' && c <= 'z') c -= 32;
    int v = base32CharValue(c);
    if (v < 0) continue;
    buf = (buf << 5) | v;
    bits += 5;
    if (bits >= 8) { bits -= 8; out.push_back((buf >> bits) & 0xFF); }
  }
  return out;
}

bool hmac_sha1(const uint8_t* key, size_t klen,
               const uint8_t* msg, size_t mlen,
               uint8_t out[20]) {
  const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
  if (!info) return false;
  mbedtls_md_context_t ctx; mbedtls_md_init(&ctx);
  bool ok =
    mbedtls_md_setup(&ctx, info, 1)         == 0 &&
    mbedtls_md_hmac_starts(&ctx, key, klen) == 0 &&
    mbedtls_md_hmac_update(&ctx, msg, mlen) == 0 &&
    mbedtls_md_hmac_finish(&ctx, out)       == 0;
  mbedtls_md_free(&ctx);
  return ok;
}

uint32_t generateTOTP(const std::vector<uint8_t>& key, uint64_t t) {
  uint64_t counter = t / TOTP_STEP;
  uint8_t msg[8];
  for (int i = 7; i >= 0; i--) { msg[i] = counter & 0xFF; counter >>= 8; }
  uint8_t hash[20];
  if (!hmac_sha1(key.data(), key.size(), msg, 8, hash)) return 0;
  int off = hash[19] & 0x0F;
  uint32_t bin =
    ((uint32_t)(hash[off]   & 0x7F) << 24) |
    ((uint32_t)(hash[off+1] & 0xFF) << 16) |
    ((uint32_t)(hash[off+2] & 0xFF) <<  8) |
    ((uint32_t)(hash[off+3] & 0xFF));
  uint32_t mod = 1;
  for (int i = 0; i < TOTP_DIGITS; i++) mod *= 10;
  return bin % mod;
}

#define SCREEN_W 128
#define SCREEN_H  32
Adafruit_SSD1306 display(SCREEN_W, SCREEN_H, &Wire, -1);

void displayInit() {
  Wire.begin(4, 3);
  Wire.setClock(100000);
  if (!display.begin(SSD1306_SWITCHCAPVCC, 0x3C)) {
    Serial.println("ERR:oled_not_found");
    while (1);
  }
  display.clearDisplay();
  display.setTextColor(SSD1306_WHITE);
  display.setRotation(2);
}

void showTOTP(uint32_t otp, int remaining, const char* name) {
  display.clearDisplay();
  display.setTextSize(1); display.setCursor(0, 0); display.println(name);
  char buf[8]; snprintf(buf, sizeof(buf), "%06u", (unsigned)otp);
  display.setTextSize(2); display.setCursor(0, 12); display.print(buf);
  display.setTextSize(1); display.setCursor(96, 14);
  display.printf("%ds", remaining);
  display.display();
}

void showMsg(const char* line1, const char* line2 = nullptr, int sz1 = 1) {
  display.clearDisplay();
  display.setTextSize(sz1); display.setCursor(0, 0); display.println(line1);
  if (line2) { display.setTextSize(1); display.setCursor(0, 20); display.println(line2); }
  display.display();
}

void showPINEntry(const char* label, int* digits, int index) {
  display.clearDisplay();
  display.setTextSize(1); display.setCursor(0, 0); display.println(label);
  display.setTextSize(2); display.setCursor(0, 12);
  for (int i = 0; i < 5; i++) {
    if (i < index) {
      display.print('*');
    } else if (i == index) {
      display.print((char)('0' + digits[i]));
    } else {
      display.print('_');
    }
    display.print(' ');
  }
  display.display();
}

void nvsClearAll() {
  prefs.begin("totp", false);
  prefs.clear();
  prefs.end();
  accounts.clear(); secretKeys.clear(); currentAccount = 0;
  strncpy(currentPIN, DEFAULT_PIN, sizeof(currentPIN));
}

void nvsLoad() {
  accounts.clear(); secretKeys.clear();
  prefs.begin("totp", true);
  int count = prefs.getInt("count", 0);
  String pin = prefs.getString("pin", DEFAULT_PIN);
  strncpy(currentPIN, pin.c_str(), sizeof(currentPIN));
  currentPIN[5] = '\0';
  for (int i = 0; i < count; i++) {
    char kN[12], kS[12];
    snprintf(kN, sizeof(kN), "name_%d", i);
    snprintf(kS, sizeof(kS), "sec_%d",  i);
    TOTPAccount acc;
    acc.name         = prefs.getString(kN, "");
    acc.base32Secret = prefs.getString(kS, "");
    if (acc.name.length() && acc.base32Secret.length()) {
      accounts.push_back(acc);
      secretKeys.push_back(base32Decode(acc.base32Secret.c_str()));
    }
  }
  prefs.end();
  if (currentAccount >= (int)accounts.size()) currentAccount = 0;
}

void nvsSaveAll() {
  prefs.begin("totp", false);
  prefs.clear();
  prefs.putString("pin", currentPIN);
  prefs.putInt("count", (int)accounts.size());
  for (int i = 0; i < (int)accounts.size(); i++) {
    char kN[12], kS[12];
    snprintf(kN, sizeof(kN), "name_%d", i);
    snprintf(kS, sizeof(kS), "sec_%d",  i);
    prefs.putString(kN, accounts[i].name);
    prefs.putString(kS, accounts[i].base32Secret);
  }
  prefs.end();
}

int nvsGetFailCount() {
  prefs.begin("totp", true);
  int n = prefs.getInt("fail_cnt", 0);
  prefs.end();
  return n;
}

void nvsSetFailCount(int n) {
  prefs.begin("totp", false);
  prefs.putInt("fail_cnt", n);
  prefs.end();
}

void readPINFromButtons(const char* label, char out[6]) {
  delay(200);
  int digits[5] = {};
  int idx = 0;
  int prevA = HIGH, prevC = HIGH;
  unsigned long dbA = 0, dbC = 0;
  const unsigned long DB = 50;

  while (idx < 5) {
    int btnA = digitalRead(BUTTON_CYCLE);
    int btnC = digitalRead(BUTTON_CONFIRM);

    if (btnA == LOW && prevA == HIGH && millis() - dbA > DB) {
      digits[idx] = (digits[idx] + 1) % 10;
      dbA = millis();
    }
    if (btnC == LOW && prevC == HIGH && millis() - dbC > DB) {
      dbC = millis();
      idx++;
    }
    prevA = btnA; prevC = btnC;
    showPINEntry(label, digits, idx < 5 ? idx : 4);
    delay(40);
  }
  for (int i = 0; i < 5; i++) out[i] = '0' + digits[i];
  out[5] = '\0';
}

void setPINFlow() {
  showMsg("Set PIN", "enter old PIN");
  delay(800);

  char oldEntered[6], newA[6], newB[6];
  readPINFromButtons("Old PIN:", oldEntered);

  if (strcmp(oldEntered, currentPIN) != 0) {
    showMsg("Wrong PIN!", nullptr, 2);
    delay(1500);
    return;
  }

  showMsg("New PIN:", nullptr, 1);
  delay(400);
  readPINFromButtons("New PIN:", newA);
  delay(400);
  showMsg("Confirm PIN:", nullptr, 1);
  delay(400);
  readPINFromButtons("Confirm:", newB);

  if (strcmp(newA, newB) != 0) {
    showMsg("Mismatch!", "PIN unchanged", 1);
    delay(1500);
    return;
  }

  strncpy(currentPIN, newA, sizeof(currentPIN));
  nvsSaveAll();
  showMsg("PIN saved!", nullptr, 2);
  delay(1200);
}

bool tryPIN(const char* entered) {
  if (strcmp(entered, currentPIN) == 0) {
    nvsSetFailCount(0);
    return true;
  }
  int fails = nvsGetFailCount() + 1;
  if (fails >= MAX_FAIL) {
    nvsClearAll();
    showMsg("WIPED!", "Too many tries", 2);
    delay(2000);
    ESP.restart();
  }
  nvsSetFailCount(fails);
  return false;
}

void cmdList() {
  Serial.print('[');
  for (int i = 0; i < (int)accounts.size(); i++) {
    if (i) Serial.print(',');
    String name = accounts[i].name; name.replace("\"", "'");
    Serial.printf("{\"index\":%d,\"name\":\"%s\"}", i, name.c_str());
  }
  Serial.println(']');
}

void handleCmd(String raw) {
  raw.trim();
  if (!raw.length()) return;

  if (raw.startsWith("TIME ")) {
    String val = raw.substring(5); val.trim();
    uint64_t unix = (uint64_t)val.toInt();
    if (unix < 1600000000ULL) {
      Serial.println("ERR:invalid_time");
      return;
    }
    baseUnix   = unix;
    baseMillis = millis();
    timeSynced = true;
    Serial.printf("OK:time_set:%llu\n", unix);
    return;
  }

  if (raw == "CLEAR") {
    nvsClearAll();
    Serial.println("OK:cleared");
    showMsg("WIPED!", "Rebooting...", 2);
    delay(2000);
    ESP.restart();
  }

  if (Locked) {
    Serial.println("ERR:locked");
    return;
  }

  if (raw == "STATUS") {
    Serial.printf("OK:ready:%d\n", (int)accounts.size());

  } else if (raw == "LIST") {
    cmdList();

  } else if (raw.startsWith("ADD ")) {
    String rest = raw.substring(4); rest.trim();
    int sp = rest.indexOf(' ');
    if (sp < 1) { Serial.println("ERR:format → ADD <nome> <base32>"); return; }
    String name   = rest.substring(0, sp);
    String secret = rest.substring(sp + 1); secret.trim(); secret.toUpperCase();
    if (name.length() > 12)  { Serial.println("ERR:name_max_12_chars");  return; }
    if (secret.length() < 8) { Serial.println("ERR:secret_min_8_chars"); return; }
    TOTPAccount acc; acc.name = name; acc.base32Secret = secret;
    accounts.push_back(acc);
    secretKeys.push_back(base32Decode(secret.c_str()));
    nvsSaveAll();
    Serial.printf("OK:added:%d:%s\n", (int)accounts.size() - 1, name.c_str());

  } else if (raw.startsWith("REMOVE ")) {
    int idx = raw.substring(7).toInt();
    if (idx < 0 || idx >= (int)accounts.size()) { Serial.println("ERR:index_out_of_range"); return; }
    String name = accounts[idx].name;
    accounts.erase(accounts.begin() + idx);
    secretKeys.erase(secretKeys.begin() + idx);
    if (currentAccount >= (int)accounts.size())
      currentAccount = max(0, (int)accounts.size() - 1);
    nvsSaveAll();
    Serial.printf("OK:removed:%d:%s\n", idx, name.c_str());

  } else {
    Serial.printf("ERR:unknown_command:%s\n", raw.c_str());
  }
}

void setup() {
  Serial.begin(115200);
  pinMode(BUTTON_CYCLE,   INPUT_PULLUP);
  pinMode(BUTTON_CONFIRM, INPUT_PULLUP);

  displayInit();
  showMsg("Connect app", "to sync time");

  nvsLoad();

  if (isFirstBoot()) {
    showMsg("First boot!", "Set a PIN");
    delay(1000);
    char newA[6], newB[6];
    while (true) {
      readPINFromButtons("New PIN:", newA);
      readPINFromButtons("Confirm:", newB);
      if (strcmp(newA, newB) == 0) {
        strncpy(currentPIN, newA, sizeof(currentPIN));
        nvsSaveAll();
        showMsg("PIN saved!", nullptr, 2);
        delay(1200);
        break;
      } else {
        showMsg("Mismatch!", "Retry...");
        delay(1200);
      }
    }
  } else {
    if (digitalRead(BUTTON_CONFIRM) == LOW) {
      delay(50);
      if (digitalRead(BUTTON_CONFIRM) == LOW) {
        setPINFlow();
      }
    }
  }
}

unsigned long lastDbA = 0, lastDbC = 0;
const unsigned long DB = 50;
int lastA = HIGH, lastC = HIGH;
int pwdDigits[5] = {};
int pwdIndex     = 0;

void loop() {
  if (Serial.available()) {
    String cmd = Serial.readStringUntil('\n');
    handleCmd(cmd);
  }

  int btnA = digitalRead(BUTTON_CYCLE);
  int btnC = digitalRead(BUTTON_CONFIRM);

  if (Locked) {
    showPINEntry("Password:", pwdDigits, pwdIndex);

    if (btnA == LOW && lastA == HIGH && millis() - lastDbA > DB) {
      pwdDigits[pwdIndex] = (pwdDigits[pwdIndex] + 1) % 10;
      lastDbA = millis();
    }
    if (btnC == LOW && lastC == HIGH && millis() - lastDbC > DB) {
      lastDbC = millis();
      pwdIndex++;
      if (pwdIndex >= 5) {
        char check[6] = {};
        for (int i = 0; i < 5; i++) check[i] = '0' + pwdDigits[i];
        if (tryPIN(check)) {
          Locked = false;
          showMsg("Unlocked!", nullptr, 2);
          delay(900);
        } else {
          int left = MAX_FAIL - nvsGetFailCount();
          char warnBuf[20];
          snprintf(warnBuf, sizeof(warnBuf), "%d tries left", left);
          showMsg("Wrong!", warnBuf, 2);
          delay(900);
        }
        pwdIndex = 0;
        memset(pwdDigits, 0, sizeof(pwdDigits));
      }
    }
    lastA = btnA; lastC = btnC;
    delay(40);
    return;
  }

  if (!timeSynced) {
    showMsg("Waiting for", "time sync...");
    lastA = btnA; lastC = btnC;
    delay(200);
    return;
  }

  if (accounts.empty()) {
    showMsg("No accounts", "Add with the app");
    lastA = btnA; lastC = btnC;
    delay(500);
    return;
  }

  if (btnA == LOW && lastA == HIGH && millis() - lastDbA > DB) {
    currentAccount = (currentAccount + 1) % (int)accounts.size();
    lastDbA = millis();
  }
  lastA = btnA; lastC = btnC;

  uint64_t now  = currentTime();
  int remaining = TOTP_STEP - (now % TOTP_STEP);
  uint32_t otp  = generateTOTP(secretKeys[currentAccount], now);
  showTOTP(otp, remaining, accounts[currentAccount].name.c_str());
  delay(40);
}
