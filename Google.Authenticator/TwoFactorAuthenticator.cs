//https://github.com/codebude/QRCoder
using QRCoder;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Google.Authenticator {
    /// <summary>
    /// modified from
    /// http://brandonpotter.com/2014/09/07/implementing-free-two-factor-authentication-in-net-using-google-authenticator/
    /// https://github.com/brandonpotter/GoogleAuthenticator
    /// </summary>
    public class TwoFactorAuthenticator {
        public static DateTime _epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        public TimeSpan DefaultClockDriftTolerance { get; set; }

        public TwoFactorAuthenticator() {
            DefaultClockDriftTolerance = TimeSpan.FromMinutes(5);
        }

        /// <summary>
        /// Generate a setup code for a Google Authenticator user to scan
        /// </summary>
        /// <param name="issuer">Issuer ID (the name of the system, i.e. 'MyApp'), can be omitted but not recommended https://github.com/google/google-authenticator/wiki/Key-Uri-Format </param>
        /// <param name="accountTitleNoSpaces">Account Title (no spaces)</param>
        /// <param name="accountSecretKey">Account Secret Key</param>
        /// <param name="secretIsBase32">Flag saying if accountSecretKey is in Base32 format or original secret</param>
        /// <param name="QRPixelsPerModule">Number of pixels per QR Module (2 pixels give ~ 100x100px QRCode)</param>
        /// <returns>SetupCode object</returns>
        public SetupCode GenerateSetupCode(string issuer, string accountTitleNoSpaces, string accountSecretKey, bool secretIsBase32, int QRPixelsPerModule) {
            return 
                secretIsBase32 ?
                GenerateSetupCode(issuer, accountTitleNoSpaces, Base32Encoding.ToBytes(accountSecretKey), QRPixelsPerModule) : 
                GenerateSetupCode(issuer, accountTitleNoSpaces, Encoding.UTF8.GetBytes(accountSecretKey), QRPixelsPerModule);
        }

        /// <summary>
        /// Generate a setup code for a Google Authenticator user to scan
        /// </summary>
        /// <param name="issuer">Issuer ID (the name of the system, i.e. 'MyApp'), can be omitted but not recommended https://github.com/google/google-authenticator/wiki/Key-Uri-Format </param>
        /// <param name="accountTitleNoSpaces">Account Title (no spaces)</param>
        /// <param name="accountSecretKey">Account Secret Key as byte[]</param>
        /// <param name="QRPixelsPerModule">Number of pixels per QR Module (2 = ~120x120px QRCode)</param>
        /// <returns>SetupCode object</returns>
        public SetupCode GenerateSetupCode(string issuer, string accountTitleNoSpaces, byte[] accountSecretKey, int QRPixelsPerModule) {
            if (accountTitleNoSpaces == null) { throw new NullReferenceException("Account Title is null"); }
            accountTitleNoSpaces = RemoveWhitespace(accountTitleNoSpaces);
            string encodedSecretKey = Base32Encoding.ToString(accountSecretKey);
            string provisionUrl = null;
            if (String.IsNullOrWhiteSpace(issuer)) {
                provisionUrl = String.Format("otpauth://totp/{0}?secret={1}", accountTitleNoSpaces, encodedSecretKey);
            } else {
                //  https://github.com/google/google-authenticator/wiki/Conflicting-Accounts
                // Added additional prefix to account otpauth://totp/Company:joe_example@gmail.com for backwards compatibility
                provisionUrl = String.Format("otpauth://totp/{2}:{0}?secret={1}&issuer={2}", accountTitleNoSpaces, encodedSecretKey, UrlEncode(issuer));
            }
            QRCodeGenerator qrGenerator = new QRCodeGenerator();
            QRCodeData qrCodeData = qrGenerator.CreateQrCode(provisionUrl, QRCodeGenerator.ECCLevel.Q);
            QRCode qrCode = new QRCode(qrCodeData);
            Bitmap qrCodeImage = qrCode.GetGraphic(QRPixelsPerModule);
            MemoryStream ms = new MemoryStream();
            qrCodeImage.Save(ms, ImageFormat.Bmp);
            return new SetupCode(accountTitleNoSpaces, encodedSecretKey, String.Format("data:image/png;base64,{0}", Convert.ToBase64String(ms.ToArray())));
        }

        private static string RemoveWhitespace(string str) {
            return new string(str.Where(c => !Char.IsWhiteSpace(c)).ToArray());
        }

        private string UrlEncode(string value) {
            StringBuilder result = new StringBuilder();
            string validChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~";

            foreach (char symbol in value) {
                if (validChars.IndexOf(symbol) != -1) {
                    result.Append(symbol);
                } else {
                    result.Append('%' + String.Format("{0:X2}", (int)symbol));
                }
            }

            return result.ToString().Replace(" ", "%20");
        }

        public string GeneratePINAtInterval(string accountSecretKey, long counter, int digits = 6) {
            return GenerateHashedCode(accountSecretKey, counter, digits);
        }

        internal string GenerateHashedCode(string secret, long iterationNumber, int digits = 6) {
            byte[] key = Base32Encoding.ToBytes(secret);
            return GenerateHashedCode(key, iterationNumber, digits);
        }

        internal string GenerateHashedCode(byte[] key, long iterationNumber, int digits = 6) {
            byte[] counter = BitConverter.GetBytes(iterationNumber);

            if (BitConverter.IsLittleEndian) {
                Array.Reverse(counter);
            }

            HMACSHA1 hmac = new HMACSHA1(key, true);

            byte[] hash = hmac.ComputeHash(counter);

            int offset = hash[hash.Length - 1] & 0xf;

            // Convert the 4 bytes into an integer, ignoring the sign.
            int binary =
                ((hash[offset] & 0x7f) << 24)
                | (hash[offset + 1] << 16)
                | (hash[offset + 2] << 8)
                | (hash[offset + 3]);

            int password = binary % (int)Math.Pow(10, digits);
            return password.ToString(new string('0', digits));
        }

        private long GetCurrentCounter() {
            return GetCurrentCounter(DateTime.UtcNow, _epoch, 30);
        }

        private long GetCurrentCounter(DateTime now, DateTime epoch, int timeStep) {
            return (long)(now - epoch).TotalSeconds / timeStep;
        }


        public bool ValidateTwoFactorPIN(string accountSecretKey, string twoFactorCodeFromClient) {
            return ValidateTwoFactorPIN(accountSecretKey, twoFactorCodeFromClient, DefaultClockDriftTolerance);
        }

        public bool ValidateTwoFactorPIN(string accountSecretKey, string twoFactorCodeFromClient, TimeSpan timeTolerance) {
            var codes = GetCurrentPINs(accountSecretKey, timeTolerance);
            return codes.Any(c => c == twoFactorCodeFromClient);
        }

        public string GetCurrentPIN(string accountSecretKey) {
            return GeneratePINAtInterval(accountSecretKey, GetCurrentCounter());
        }

        public string GetCurrentPIN(string accountSecretKey, DateTime now) {
            return GeneratePINAtInterval(accountSecretKey, GetCurrentCounter(now, _epoch, 30));
        }

        public string[] GetCurrentPINs(string accountSecretKey) {
            return GetCurrentPINs(accountSecretKey, DefaultClockDriftTolerance);
        }

        public string[] GetCurrentPINs(string accountSecretKey, TimeSpan timeTolerance) {
            List<string> codes = new List<string>();
            long iterationCounter = GetCurrentCounter();
            int iterationOffset = 0;

            if (timeTolerance.TotalSeconds > 30) {
                iterationOffset = Convert.ToInt32(timeTolerance.TotalSeconds / 30.00);
            }

            long iterationStart = iterationCounter - iterationOffset;
            long iterationEnd = iterationCounter + iterationOffset;

            for (long counter = iterationStart; counter <= iterationEnd; counter++) {
                codes.Add(GeneratePINAtInterval(accountSecretKey, counter));
            }

            return codes.ToArray();
        }
    }
}