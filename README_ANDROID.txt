ANDROID-FRIENDLY VERSION
This version does NOT use better-sqlite3, so it avoids the native compilation error you saw.

In Termux:
1. cd ~/Rewardly_Android_Fixed
2. rm -rf node_modules
3. npm install
4. cp .env.example .env
5. npm start
6. Open http://localhost:3000

Admin credentials are read from .env. Change them before using outside your phone.
The withdrawal system creates requests; it does NOT automatically transfer real money.
