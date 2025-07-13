gcc totp_generator.c base32.c hmac.c hotp.c sha1.c -o totp_generator -O3 -Wall -Wextra -fno-stack-protector
upx -9 totp_generator
