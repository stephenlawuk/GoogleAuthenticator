namespace Google.Authenticator {
    public class SetupCode {
        public string Account { get; internal set; }
        public string ManualEntryKey { get; internal set; }
        public string QrCodeSetupImageUrl { get; internal set; }
        public SetupCode() { }
        public SetupCode(string account, string manualentrykey, string qrcodesetupimageurl) {
            Account = account;
            ManualEntryKey = manualentrykey;
            QrCodeSetupImageUrl = qrcodesetupimageurl;
        }
    }
}