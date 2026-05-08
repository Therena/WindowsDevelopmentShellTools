# Type bootstrap for split module layout.
Set-StrictMode -Version Latest

# Full .NET Framework: PKCS types ship in System.Security. .NET Core / modern PowerShell: separate PKCS assembly.
if ($PSVersionTable.PSEdition -eq 'Core') {
    $coreLib = [object].Assembly.Location
    $pkcsPath = Join-Path $PSHOME 'System.Security.Cryptography.Pkcs.dll'
    if (-not (Test-Path -LiteralPath $pkcsPath)) {
        $pkcsPath = Join-Path (Split-Path -Parent $coreLib) 'System.Security.Cryptography.Pkcs.dll'
    }
    if (-not (Test-Path -LiteralPath $pkcsPath)) {
        throw "Could not find System.Security.Cryptography.Pkcs.dll next to the PowerShell runtime. PKCS certificate helpers require PowerShell 7 on Windows with a standard install."
    }
    $CertificateAssemblies = @($coreLib, $pkcsPath)
} else {
    $CertificateAssemblies = @(
        'System.Security, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a'
    )
}

$CertificateSource = @"
    namespace Therena.Encryption
    {
        using System;
        using System.IO;
        using System.Runtime.InteropServices;
        using System.Security.Cryptography.Pkcs;

        public static class Certificate  
        { 
            private const int CERT_QUERY_OBJECT_FILE = 0x1;
            private const int CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED = 0x400;
            private const int CERT_QUERY_FORMAT_FLAG_BINARY = 0x2;

            [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            private static extern bool CryptQueryObject(
                int dwObjectType,
                [MarshalAs(UnmanagedType.LPWStr)]
                string pvObject,
                int dwExpectedContentTypeFlags,
                int dwExpectedFormatTypeFlags,
                int dwFlags,
                ref int pdwMsgAndCertEncodingType,
                ref int pdwContentType,
                ref int pdwFormatType,
                ref IntPtr phCertStore,
                ref IntPtr phMsg,
                ref IntPtr ppvContext
            );
    
            private const int CMSG_ENCODED_MESSAGE = 29;

            [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            private static extern bool CryptMsgGetParam(
                IntPtr hCryptMsg,
                int dwParamType,
                int dwIndex,
                byte[] pvData,
                ref int pcbData
            );
    
            public static System.Security.Cryptography.Pkcs.SignerInfo[] DecodeCertificateData(byte[] pvData)
            {
                var cms = new SignedCms();
                cms.Decode(pvData);
                var infos = cms.SignerInfos;
                var certs = new System.Security.Cryptography.Pkcs.SignerInfo[infos.Count];
                for (int i = 0; i < infos.Count; i++)
                {
                    certs[i] = infos[i];
                }
                return certs;
            }

            public static System.Security.Cryptography.Pkcs.SignerInfo[] GetCertificates(string filePath)
            {
                var file = new FileInfo(filePath);

                int pdwMsgAndCertEncodingType = 0;
                int pdwContentType = 0;
                int pdwFormatType = 0;
                IntPtr phCertStore = IntPtr.Zero;
                IntPtr phMsg = IntPtr.Zero;
                IntPtr ppvContext = IntPtr.Zero;

                var result = CryptQueryObject(
                    CERT_QUERY_OBJECT_FILE,
                    file.FullName,
                    CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                    CERT_QUERY_FORMAT_FLAG_BINARY,
                    0,
                    ref pdwMsgAndCertEncodingType,
                    ref pdwContentType,
                    ref pdwFormatType,
                    ref phCertStore,
                    ref phMsg,
                    ref ppvContext);

                if (result == false)
                {
                    return new System.Security.Cryptography.Pkcs.SignerInfo[0];
                }

                int pcbData = 0;
                CryptMsgGetParam(phMsg, CMSG_ENCODED_MESSAGE, 0, null, ref pcbData);

                var pvData = new byte[pcbData];
                CryptMsgGetParam(phMsg, CMSG_ENCODED_MESSAGE, 0, pvData, ref pcbData);

                return DecodeCertificateData(pvData);
            }
        }
    }
"@

$encryptionTypeLoaded = $false
try {
    [void][Therena.Encryption.Certificate]
    $encryptionTypeLoaded = $true
} catch {
}
if (-not $encryptionTypeLoaded) {
    Add-Type -ReferencedAssemblies $CertificateAssemblies -TypeDefinition $CertificateSource -Language CSharp
}


$HexDumpSource = @"
    namespace Therena.Conversion
    {
        using System;
        using System.IO;
        using System.Text;

        
        public static class HexDump  
        {
            private const int ELEMANTPERSECTION = 8;

            public static string GetHexDump(FileInfo file, int sectionCount)
            {
                if(sectionCount <= 0)
                {
                    sectionCount = 2;
                }

                int bufferSize = ELEMANTPERSECTION * sectionCount;

                var builder = new StringBuilder();
                using (Stream fileStream = file.OpenRead())
                {
                    int position = 0;
                    var buffer = new byte[bufferSize];
                    while(position < fileStream.Length)
                    {
                        var read = fileStream.Read(buffer, 0, buffer.Length);
                        if(read > 0)
                        {
                            builder.Append(String.Format("{0:x4}: ", position));
                            position += read;

                            for(uint i = 0; i < bufferSize; ++i)
                            {
                                if(i < read)
                                {
                                    string hex = String.Format("{0:x2}", (byte)buffer[i]);
                                    builder.Append(hex + " ");
                                }
                                else
                                {
                                    builder.Append("   ");
                                }

                                if(((i + 1) % ELEMANTPERSECTION) == 0)
                                {
                                    builder.Append("-- ");
                                }

                                if(buffer[i] < 32 || buffer[i] > 250)
                                {
                                    buffer[i] = (byte)'.';
                                }
                            }

                            string bufferContent = Encoding.Default.GetString(buffer);
                            if(bufferContent.Length > read)
                            {
                                bufferContent = bufferContent.Substring(0, read);
                            }
                            builder.Append(bufferContent + Environment.NewLine);
                        }
                    }
                }
                return builder.ToString();
            }
        }
    }
"@

Add-Type -TypeDefinition $HexDumpSource -Language CSharp


if (-not ([System.Management.Automation.PSTypeName]'Therena.WindowsDevelopmentShellTools.WindowsErrorInteropWds4').Type) {
    Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Therena.WindowsDevelopmentShellTools
{
    internal static class NativeMethods
    {
        internal const uint FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000;
        internal const uint FORMAT_MESSAGE_FROM_HMODULE = 0x00000800;
        internal const uint FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200;

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint FormatMessage(
            uint dwFlags,
            IntPtr lpSource,
            uint dwMessageId,
            uint dwLanguageId,
            StringBuilder lpBuffer,
            uint nSize,
            IntPtr Arguments);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        internal static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("ntdll.dll")]
        internal static extern uint RtlNtStatusToDosError(int status);
    }

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    internal delegate int RtlDosErrorToNtStatusDelegate(uint dosError);

    public static class WindowsErrorInteropWds4
    {
        private static readonly IntPtr NtdllModule = NativeMethods.LoadLibrary("ntdll.dll");
        private static readonly RtlDosErrorToNtStatusDelegate RtlDosErrorToNtStatusFn = InitRtlDosErrorToNtStatus();

        private static RtlDosErrorToNtStatusDelegate InitRtlDosErrorToNtStatus()
        {
            if (NtdllModule == IntPtr.Zero)
            {
                return null;
            }
            IntPtr p = NativeMethods.GetProcAddress(NtdllModule, "RtlDosErrorToNtStatus");
            if (p == IntPtr.Zero)
            {
                return null;
            }
            return Marshal.GetDelegateForFunctionPointer<RtlDosErrorToNtStatusDelegate>(p);
        }

// Win32->NTSTATUS table reconstruction (see https://gist.github.com/alastorid/9a71ace47e590ab8237c133eaec4ef60 ); candidates are filtered with RtlNtStatusToDosError and prefer 0xCâ€¦ NTSTATUS shape.
        private static readonly ushort[] RtlpStatusTableDosToNt = new ushort[]
{
            
0x0000, 0x03e5, 0x00ea, 0x0514, 0x0515, 0x03fe, 0x0516, 0x2009, 0x0057, 0x0517, 0x0460, 0x03f6, 0x0461, 0x0518, 0x20ac, 0x0720, 0x0779, 0x19d3, 0x0001, 0x8000, 0x03e6, 0x0000, 0x0003, 0x8000, 0x0004, 0x8000, 0x00ea, 0x0000, 0x0012, 0x0000, 0x056f, 0x012b, 0x001c, 0x0015, 0x0015, 0x00aa, 0x0103, 0x00fe, 0x00ff, 0x00ff, 0x0456, 0x0103, 0x044d, 0x0456, 0x0457, 0x044c, 0x044e, 0x044f, 0x0450, 0x0962, 0x10f4, 0x048d, 0x048e, 0x05aa, 0x0006, 0x0001, 0x0035, 0x054f, 0x0554, 0x0120, 0x0554, 0x0057, 0x0057, 0x0032, 0x0558, 0x052e, 0x0057, 0x0520, 0x0005, 0x0005, 0x051f, 0x0554, 0x078b, 0x06f8, 0x0057, 0x007a, 0x0574, 0x06fe, 0x0057, 0x0057, 0x0532, 0x1770, 0x1771, 0x0001, 0x0558, 0x0545, 0x0575, 0x0575, 0x0575, 0x0575, 0x13c5, 0x13c6, 0x13c7, 0x13c8, 0x13c9, 0x19e5, 0x001f, 0x0001, 0x0057, 0x0018, 0x03e6, 0x03e7, 0x05ae, 0x0006, 0x03e9, 0x00c1, 0x0057, 0x0057, 0x0000, 0x0002, 0x0000, 0x0002, 0x0000, 0x0001, 0x0000, 0x0026, 0x0000, 0x0022, 0x0000, 0x0015, 0x0000, 0x06f9, 0x0000, 0x001b, 0x0000, 0x00ea, 0x0000, 0x0008, 0x0000, 0x01e7, 0x0000, 0x01e7, 0x0000, 0x0057, 0x0000, 0x0057, 0x0000, 0x0001, 0x0000, 0x001d, 0xc000, 0x0005, 0x0000, 0x0005, 0x0000, 0x00c1, 0x0000, 0x0005, 0x0000, 0x0005, 0x0000, 0x007a, 0x0000, 0x0006, 0x0000, 0x0025, 0xc000, 0x0026, 0xc000, 0x009e, 0x0000, 0x002b, 0xc000, 0x01e7, 0x0000, 0x01e7, 0x0000, 0x0057, 0x0571, 0x007b, 0x0002, 0x00b7, 0x0006, 0x00a1, 0x0000, 0x0003, 0x0000, 0x00a1, 0x0000, 0x045d, 0x0000, 0x045d, 0x0000, 0x0017, 0x0000, 0x0017, 0x0000, 0x0008, 0x0000, 0x0005, 0x0000, 0x0006, 0x0000, 0x0020, 0x0000, 0x0718, 0x0000, 0x0057, 0x0000, 0x0120, 0x0000, 0x012a, 0x0000, 0x0057, 0x0000, 0x0057, 0x0000, 0x009c, 0x0000, 0x0005, 0x0000, 0x0057, 0x0000, 0x0057, 0x0000, 0x0057, 0x0000, 0x011a, 0x0000, 0x00ff, 0x0000, 0x0570, 0x0000, 0x0570, 0x0000, 0x0570, 0x0000, 0x0021, 0x0000, 0x0021, 0x0000, 0x0005, 0x0000, 0x0032, 0x0000, 0x0519, 0x0000, 0x051a, 0x0000, 0x051b, 0x0000, 0x051c, 0x0000, 0x051d, 0x0000, 0x051e, 0x0000, 0x051f, 0x0000, 0x0520, 0x0000, 0x0521, 0x0000, 0x0522, 0x0000, 0x0523, 0x0000, 0x0524, 0x0000, 0x0525, 0x0000, 0x0526, 0x0000, 0x0527, 0x0000, 0x0528, 0x0000, 0x0529, 0x0000, 0x052a, 0x0000, 0x0056, 0x0000, 0x052c, 0x0000, 0x052d, 0x0000, 0x052e, 0x0000, 0x052f, 0x0000, 0x0530, 0x0000, 0x0531, 0x0000, 0x0532, 0x0000, 0x0533, 0x0000, 0x0534, 0x0000, 0x0535, 0x0000, 0x0536, 0x0000, 0x0537, 0x0000, 0x0538, 0x0000, 0x0539, 0x0000, 0x053a, 0x0000, 0x007f, 0x0000, 0x00c1, 0x0000, 0x03f0, 0x0000, 0x053c, 0x0000, 0x009e, 0x0000, 0x0070, 0x0000, 0x053d, 0x0000, 0x053e, 0x0000, 0x0044, 0x0000, 0x0103, 0x0000, 0x053f, 0x0000, 0x0103, 0x0000, 0x009a, 0x0000, 0x000e, 0x0000, 0x01e7, 0x0000, 0x0714, 0x0000, 0x0715, 0x0000, 0x0716, 0x0000, 0x008c, 0xc000, 0x008d, 0xc000, 0x008e, 0xc000, 0x008f, 0xc000, 0x0090, 0xc000, 0x0091, 0xc000, 0x0092, 0xc000, 0x0093, 0xc000, 0x0094, 0xc000, 0x0216, 0x0000, 0x0096, 0xc000, 0x0008, 0x0000, 0x03ee, 0x0000, 0x0540, 0x0000, 0x05aa, 0x0000, 0x0003, 0x0000, 0x0017, 0x0000, 0x048f, 0x0000, 0x0015, 0x0000, 0x01e7, 0x0000, 0x01e7, 0x0000, 0x05ad, 0x0000, 0x0013, 0x0000, 0x0015, 0x0000, 0x0541, 0x0000, 0x0542, 0x0000, 0x0543, 0x0000, 0x0544, 0x0000, 0x0545, 0x0000, 0x0057, 0x0000, 0x00e7, 0x00e7, 0x00e6, 0x00e7, 0x0001, 0x00e9, 0x00e8, 0x0217, 0x0218, 0x00e6, 0x0079, 0x0026, 0x0005, 0x0032, 0x0033, 0x0034, 0x0035, 0x0036, 0x0037, 0x0038, 0x0039, 0x003a, 0x003b, 0x003c, 0x003d, 0x003e, 0x003f, 0x0040, 0x0041, 0x0042, 0x0043, 0x0044, 0x0045, 0x0046, 0x0047, 0x0048, 0x0058, 0x0011, 0x0005, 0x00f0, 0x0546, 0x00e8, 0x0547, 0x0548, 0x0549, 0x054a, 0x054b, 0x054c, 0x054d, 0x012c, 0x012d, 0x054e, 0x054f, 0x0550, 0x0551, 0x06f8, 0x045d, 0x0552, 0x0553, 0x0057, 0x0057, 0x0057, 0x0057, 0x0057, 0x0057, 0x0057, 0x0057, 0x0057, 0x0057, 0x0057, 0x0057, 0x0003, 0x0420, 0x03e9, 0x0554, 0x00cb, 0x0091, 0x0570, 0x010b, 0x0555, 0x0556, 0x00ce, 0x0961, 0x0964, 0x013d, 0x0005, 0x0557, 0x0558, 0x0420, 0x05a4, 0x00c1, 0x0559, 0x055a, 0x03ee, 0x0004, 0x03e3, 0x0005, 0x04ba, 0x0005, 0x055b, 0x055c, 0x055d, 0x055e, 0x0006, 0x055f, 0x05af, 0x00c1, 0x00c1, 0x00c1, 0x00c1, 0x0576, 0x007e, 0x00b6, 0x007f, 0x0040, 0x0040, 0x0033, 0x003b, 0x003b, 0x003b, 0x003b, 0x045a, 0x007c, 0x0056, 0x006d, 0x03f1, 0x03f8, 0x03ed, 0x045e, 0x0560, 0x0561, 0x0562, 0x0563, 0x0564, 0x0565, 0x0566, 0x0567, 0x03ef, 0x0568, 0x0569, 0x03f9, 0x056a, 0x045d, 0x04db, 0x0459, 0x0462, 0x0463, 0x0464, 0x0465, 0x0466, 0x0467, 0x0468, 0x045f, 0x045d, 0x0451, 0x0452, 0x0453, 0x0454, 0x0455, 0x0469, 0x0458, 0x056b, 0x056c, 0x03fa, 0x03fb, 0x056d, 0x056e, 0x03fc, 0x03fd, 0x0057, 0x045d, 0x0016, 0x045d, 0x045d, 0x05de, 0x0013, 0x06fa, 0x06fb, 0x06fc, 0x06fd, 0x05dc, 0x05dd, 0x06fe, 0x0700, 0x0701, 0x046b, 0x04c3, 0x04c4, 0x05df, 0x070f, 0x0710, 0x0711, 0x0712, 0x0572, 0x003b, 0x003b, 0x0717, 0x046a, 0x06f8, 0x04be, 0x04be, 0x0044, 0x0034, 0x0040, 0x0040, 0x0040, 0x0044, 0x003b, 0x003b, 0x003b, 0x003b, 0x003b, 0x003b, 0x003b, 0x0032, 0x0032, 0x17e6, 0x046c, 0x00c1, 0x0773, 0x0490, 0x04ff, 0x0057, 0x0000, 0x022a, 0xc000, 0x022b, 0xc000, 0x04d5, 0x0492, 0x0774, 0x0775, 0x0006, 0x04c9, 0x04ca, 0x04cb, 0x04cc, 0x04cd, 0x04ce, 0x04cf, 0x04d0, 0x04d1, 0x04d2, 0x04d3, 0x04d4, 0x04c8, 0x04d6, 0x04d7, 0x04d8, 0x00c1, 0x04d4, 0x054f, 0x04d0, 0x0573, 0x0422, 0x00b6, 0x007f, 0x0120, 0x0476, 0x10fe, 0x1b8e, 0x07d1, 0x04b1, 0x0015, 0x0491, 0x1126, 0x1129, 0x112a, 0x1128, 0x0780, 0x0781, 0x00a1, 0x0488, 0x0489, 0x048a, 0x048b, 0x048c, 0x0005, 0x0005, 0x0005, 0x0005, 0x0005, 0x0005, 0x1777, 0x1778, 0x1772, 0x1068, 0x1069, 0x106a, 0x106b, 0x201a, 0x201b, 0x201c, 0x0001, 0x10ff, 0x1100, 0x0494, 0x200a, 0x200b, 0x200c, 0x200d, 0x200e, 0x200f, 0x2010, 0x2011, 0x2012, 0x2013, 0x2014, 0x2015, 0x2016, 0x2017, 0x2018, 0x2019, 0x211e, 0x1127, 0x0651, 0x049a, 0x049b, 0x2024, 0x0575, 0x03e6, 0x1075, 0x1076, 0x04ed, 0x10e8, 0x2138, 0x04e3, 0x2139, 0x049d, 0x213a, 0x2141, 0x2142, 0x2143, 0x2144, 0x2145, 0x2146, 0x2147, 0x2148, 0x2149, 0x0032, 0x2151, 0x2152, 0x2153, 0x2154, 0x215d, 0x2163, 0x2164, 0x2165, 0x216d, 0x0577, 0x0052, 0x2171, 0x0000, 0x2172, 0x0000, 0x0333, 0x8009, 0x0334, 0x8009, 0x0002, 0x0000, 0x0335, 0x8009, 0x0336, 0x8009, 0x0337, 0x8009, 0x0338, 0x8009, 0x0339, 0x8009, 0x033a, 0x8009, 0x033b, 0x8009, 0x033c, 0x8009, 0x033d, 0x8009, 0x033e, 0x8009, 0x0340, 0x8009, 0x0341, 0x8009, 0x0342, 0x8009, 0x045b, 0x0000, 0x04e7, 0x0000, 0x04e6, 0x0000, 0x106f, 0x0000, 0x1074, 0x0000, 0x106e, 0x0000, 0x012e, 0x0000, 0x0305, 0x8003, 0x0306, 0x8003, 0x0307, 0x8003, 0x0308, 0x8003, 0x0309, 0x8003, 0x030a, 0x8003, 0x030b, 0x8003, 0x04ef, 0x0000, 0x04f0, 0x0000, 0x0348, 0x8009, 0x04e8, 0x0000, 0x0343, 0x8009, 0x177d, 0x0000, 0x0504, 0x0001, 0xc009, 0x217c, 0x0000, 0x2182, 0x0000, 0x00c1, 0x0000, 0x00c1, 0x0000, 0x0346, 0x8009, 0x0572, 0x0000, 0x04ec, 0x04ec, 0x04ec, 0x04ec, 0x04fb, 0x04fb, 0x04fc, 0x006b, 0x8010, 0x006c, 0x8010, 0x006f, 0x8010, 0x000c, 0x8010, 0x000d, 0x8009, 0x002c, 0x8010, 0x0016, 0x8009, 0x002f, 0x8010, 0x04f1, 0x0000, 0x0351, 0x8009, 0x0352, 0x8009, 0x0353, 0x8009, 0x0354, 0x8009, 0x0355, 0x8009, 0x0022, 0x8009, 0x078c, 0x078d, 0x078e, 0x217b, 0x219d, 0x219f, 0x052e, 0x0000, 0x0502, 0x0000, 0x0356, 0x8009, 0x0357, 0x8009, 0x0358, 0x8009, 0x0359, 0x8009, 0x035a, 0x8009, 0x035b, 0x8009, 0x0503, 0x0000, 0x0505, 0x078f, 0x0506, 0x06a4, 0x06a5, 0x0006, 0x06a7, 0x06a8, 0x06a9, 0x06aa, 0x06ab, 0x06ac, 0x06ad, 0x06ae, 0x06af, 0x06b0, 0x06b1, 0x06b2, 0x06b3, 0x06b4, 0x06b5, 0x06b6, 0x06b7, 0x06b8, 0x06b9, 0x06ba, 0x06bb, 0x06bc, 0x06bd, 0x06be, 0x06bf, 0x06c0, 0x06c2, 0x06c4, 0x06c5, 0x06c6, 0x06c7, 0x06c8, 0x06c9, 0x06cb, 0x06cc, 0x06cd, 0x06ce, 0x06cf, 0x06d0, 0x06d1, 0x06d2, 0x06d3, 0x06d4, 0x06d5, 0x06d6, 0x06d7, 0x06d8, 0x06d9, 0x06da, 0x06db, 0x06dc, 0x06dd, 0x06de, 0x06df, 0x06e0, 0x06e1, 0x06e2, 0x06e3, 0x06e4, 0x06e5, 0x06e6, 0x06e7, 0x06e8, 0x06e9, 0x06ea, 0x06eb, 0x06ff, 0x070e, 0x076a, 0x076b, 0x076c, 0x0719, 0x071a, 0x071b, 0x071c, 0x071d, 0x071e, 0x071f, 0x0721, 0x0722, 0x077a, 0x077b, 0x06ec, 0x06ed, 0x06ee, 0x0006, 0x0006, 0x06f1, 0x06f2, 0x06f3, 0x06f4, 0x06f5, 0x06f6, 0x06f7, 0x0723, 0x0724, 0x0725, 0x0726, 0x0727, 0x0728, 0x077c, 0x077d, 0x077e, 0x1b59, 0x1b5a, 0x1b5b, 0x1b5f, 0x1b60, 0x1b61, 0x1b62, 0x1b63, 0x1b64, 0x1b65, 0x1b66, 0x1b67, 0x1b68, 0x1b69, 0x1b8f, 0x1b8e, 0x1b90, 0x1b6e, 0x1b6f, 0x1b70, 0x1b71, 0x1b7b, 0x1b7e, 0x1b80, 0x1b81, 0x1b82, 0x1b84, 0x1b85, 0x1b89, 0x1b5c, 0x1b8a, 0x1b8b, 0x1b8d, 0x1b8c, 0x1b92, 0x1b91, 0x13af, 0x13b0, 0x13b1, 0x13b2, 0x13b3, 0x13b4, 0x13b5, 0x13b6, 0x13b7, 0x13b8, 0x13b9, 0x13ba, 0x13bb, 0x13bc, 0x13bd, 0x13be, 0x13c0, 0x13ce, 0x13c2, 0x13c3, 0x13c4, 0x36b0, 0x36b1, 0x36b2, 0x36b3, 0x36b4, 0x36b5, 0x36b6, 0x36b7, 0x36b9, 0x36ba, 0x36bb, 0x19c8, 0x19c9, 0x19ca, 0x19cb, 0x19cc, 0x19cd, 0x19ce, 0x19cf, 0x19d0, 0x19d1, 0x19d2, 0x19d4, 0x19d5, 0x19d6, 0x19d7, 0x19d8, 0x19d9, 0x19da, 0x19db, 0x19dc, 0x19dd, 0x19de, 0x19df, 0x19e0, 0x19e1, 0x19e2, 0x19e3, 0x19e4, 0x19e6, 0x19e7, 0x19e8, 0x19e9, 0x19ea, 0x19eb, 0x19ec, 0x19ed, 0x19ee, 0x19ef, 0x19f0, 0x19f1, 0x19f2, 0x19f3, 0x19f4, 0x19f5, 0x19f6, 0x0037, 0x0037, 0x0037, 0x0000, 0x0,
        };

        private struct RunEntryDosToNt
        {
            public RunEntryDosToNt(uint baseCode, ushort runLength, ushort codeSize)
            {
                BaseCode = baseCode;
                RunLength = runLength;
                CodeSize = codeSize;
            }
            public readonly uint BaseCode;
            public readonly ushort RunLength;
            public readonly ushort CodeSize;
        }

        private static readonly RunEntryDosToNt[] RtlpRunTableDosToNt = new RunEntryDosToNt[]
        {
            new RunEntryDosToNt(0x00000000u, 0x0001, 0x0001),
            new RunEntryDosToNt(0x00000103u, 0x0001, 0x0001),
            new RunEntryDosToNt(0x00000105u, 0x0003, 0x0001),
            new RunEntryDosToNt(0x0000010cu, 0x0002, 0x0001),
            new RunEntryDosToNt(0x00000121u, 0x0001, 0x0001),
            new RunEntryDosToNt(0x40000002u, 0x0001, 0x0001),
            new RunEntryDosToNt(0x40000006u, 0x0001, 0x0001),
            new RunEntryDosToNt(0x40000008u, 0x0002, 0x0001),
            new RunEntryDosToNt(0x4000000cu, 0x0002, 0x0001),
            new RunEntryDosToNt(0x40000370u, 0x0001, 0x0001),
            new RunEntryDosToNt(0x40020056u, 0x0001, 0x0001),
            new RunEntryDosToNt(0x400200afu, 0x0001, 0x0001),
            new RunEntryDosToNt(0x401a000cu, 0x0001, 0x0001),
            new RunEntryDosToNt(0x80000001u, 0x0006, 0x0002),
            new RunEntryDosToNt(0x8000000bu, 0x0001, 0x0001),
            new RunEntryDosToNt(0x8000000du, 0x000a, 0x0001),
            new RunEntryDosToNt(0x8000001au, 0x0006, 0x0001),
            new RunEntryDosToNt(0x80000021u, 0x0002, 0x0001),
            new RunEntryDosToNt(0x80000025u, 0x0001, 0x0001),
            new RunEntryDosToNt(0x80000027u, 0x0001, 0x0001),
            new RunEntryDosToNt(0x80000288u, 0x0002, 0x0001),
            new RunEntryDosToNt(0x80090300u, 0x0012, 0x0001),
            new RunEntryDosToNt(0x80090316u, 0x0003, 0x0001),
            new RunEntryDosToNt(0x80090320u, 0x0003, 0x0001),
            new RunEntryDosToNt(0x80090325u, 0x0005, 0x0001),
            new RunEntryDosToNt(0x80090330u, 0x0002, 0x0001),
            new RunEntryDosToNt(0x80090347u, 0x0001, 0x0001),
            new RunEntryDosToNt(0x80090349u, 0x0001, 0x0001),
            new RunEntryDosToNt(0x80092010u, 0x0001, 0x0001),
            new RunEntryDosToNt(0x80092012u, 0x0002, 0x0001),
            new RunEntryDosToNt(0x80096004u, 0x0001, 0x0001),
            new RunEntryDosToNt(0x80130001u, 0x0005, 0x0001),
            new RunEntryDosToNt(0x80190009u, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc0000001u, 0x000b, 0x0001),
            new RunEntryDosToNt(0xc000000du, 0x001a, 0x0002),
            new RunEntryDosToNt(0xc000002au, 0x0004, 0x0002),
            new RunEntryDosToNt(0xc0000030u, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc0000032u, 0x0004, 0x0001),
            new RunEntryDosToNt(0xc0000037u, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc0000039u, 0x0071, 0x0002),
            new RunEntryDosToNt(0xc00000abu, 0x000c, 0x0001),
            new RunEntryDosToNt(0xc00000bau, 0x0019, 0x0001),
            new RunEntryDosToNt(0xc00000d4u, 0x0004, 0x0001),
            new RunEntryDosToNt(0xc00000d9u, 0x0002, 0x0001),
            new RunEntryDosToNt(0xc00000dcu, 0x000e, 0x0001),
            new RunEntryDosToNt(0xc00000edu, 0x0012, 0x0001),
            new RunEntryDosToNt(0xc0000100u, 0x000c, 0x0001),
            new RunEntryDosToNt(0xc000010du, 0x0002, 0x0001),
            new RunEntryDosToNt(0xc0000117u, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc000011bu, 0x000e, 0x0001),
            new RunEntryDosToNt(0xc000012bu, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc000012du, 0x0005, 0x0001),
            new RunEntryDosToNt(0xc0000133u, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc0000135u, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc0000138u, 0x0002, 0x0001),
            new RunEntryDosToNt(0xc000013bu, 0x0008, 0x0001),
            new RunEntryDosToNt(0xc0000148u, 0x0002, 0x0001),
            new RunEntryDosToNt(0xc000014bu, 0x0003, 0x0001),
            new RunEntryDosToNt(0xc000014fu, 0x000f, 0x0001),
            new RunEntryDosToNt(0xc000015fu, 0x0002, 0x0001),
            new RunEntryDosToNt(0xc0000162u, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc0000165u, 0x0009, 0x0001),
            new RunEntryDosToNt(0xc0000172u, 0x0007, 0x0001),
            new RunEntryDosToNt(0xc000017au, 0x000d, 0x0001),
            new RunEntryDosToNt(0xc0000188u, 0x0009, 0x0001),
            new RunEntryDosToNt(0xc0000192u, 0x000a, 0x0001),
            new RunEntryDosToNt(0xc0000202u, 0x0002, 0x0001),
            new RunEntryDosToNt(0xc0000203u, 0x0015, 0x0001),
            new RunEntryDosToNt(0xc000021cu, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc0000220u, 0x0002, 0x0001),
            new RunEntryDosToNt(0xc0000224u, 0x0002, 0x0001),
            new RunEntryDosToNt(0xc0000227u, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc0000229u, 0x0003, 0x0002),
            new RunEntryDosToNt(0xc000022du, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc0000230u, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc0000233u, 0x000f, 0x0001),
            new RunEntryDosToNt(0xc0000243u, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc0000246u, 0x0004, 0x0001),
            new RunEntryDosToNt(0xc0000253u, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc0000253u, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc0000257u, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc0000259u, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc000025eu, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc0000262u, 0x0004, 0x0001),
            new RunEntryDosToNt(0xc0000267u, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc000026au, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc000026cu, 0x0003, 0x0001),
            new RunEntryDosToNt(0xc0000272u, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc0000275u, 0x0005, 0x0001),
            new RunEntryDosToNt(0xc0000280u, 0x0002, 0x0001),
            new RunEntryDosToNt(0xc0000283u, 0x0005, 0x0001),
            new RunEntryDosToNt(0xc000028au, 0x0002, 0x0001),
            new RunEntryDosToNt(0xc000028du, 0x0007, 0x0001),
            new RunEntryDosToNt(0xc0000295u, 0x000b, 0x0001),
            new RunEntryDosToNt(0xc00002a1u, 0x0012, 0x0001),
            new RunEntryDosToNt(0xc00002b6u, 0x0003, 0x0001),
            new RunEntryDosToNt(0xc00002c1u, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc00002c3u, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc00002c5u, 0x0003, 0x0001),
            new RunEntryDosToNt(0xc00002c9u, 0x0005, 0x0001),
            new RunEntryDosToNt(0xc00002cfu, 0x0002, 0x0001),
            new RunEntryDosToNt(0xc00002d4u, 0x000a, 0x0001),
            new RunEntryDosToNt(0xc00002dfu, 0x0009, 0x0001),
            new RunEntryDosToNt(0xc00002e9u, 0x0002, 0x0001),
            new RunEntryDosToNt(0xc00002ecu, 0x0020, 0x0002),
            new RunEntryDosToNt(0xc0000320u, 0x0003, 0x0002),
            new RunEntryDosToNt(0xc0000350u, 0x0003, 0x0002),
            new RunEntryDosToNt(0xc0000354u, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc0000356u, 0x0007, 0x0002),
            new RunEntryDosToNt(0xc0000361u, 0x0004, 0x0001),
            new RunEntryDosToNt(0xc000036bu, 0x0002, 0x0001),
            new RunEntryDosToNt(0xc000036fu, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc0000380u, 0x000e, 0x0002),
            new RunEntryDosToNt(0xc000038fu, 0x0001, 0x0002),
            new RunEntryDosToNt(0xc0000401u, 0x0006, 0x0001),
            new RunEntryDosToNt(0xc0000408u, 0x0009, 0x0002),
            new RunEntryDosToNt(0xc0000412u, 0x0003, 0x0001),
            new RunEntryDosToNt(0xc0020001u, 0x001d, 0x0001),
            new RunEntryDosToNt(0xc002001fu, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc0020021u, 0x0006, 0x0001),
            new RunEntryDosToNt(0xc0020028u, 0x0026, 0x0001),
            new RunEntryDosToNt(0xc002004fu, 0x0007, 0x0001),
            new RunEntryDosToNt(0xc0020057u, 0x0002, 0x0001),
            new RunEntryDosToNt(0xc0020062u, 0x0002, 0x0001),
            new RunEntryDosToNt(0xc0030001u, 0x000c, 0x0001),
            new RunEntryDosToNt(0xc0030059u, 0x0009, 0x0001),
            new RunEntryDosToNt(0xc00a0001u, 0x0003, 0x0001),
            new RunEntryDosToNt(0xc00a0006u, 0x000b, 0x0001),
            new RunEntryDosToNt(0xc00a0012u, 0x0007, 0x0001),
            new RunEntryDosToNt(0xc00a0022u, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc00a0024u, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc00a0026u, 0x0003, 0x0001),
            new RunEntryDosToNt(0xc00a002au, 0x0002, 0x0001),
            new RunEntryDosToNt(0xc00a002eu, 0x0004, 0x0001),
            new RunEntryDosToNt(0xc00a0033u, 0x0004, 0x0001),
            new RunEntryDosToNt(0xc0130001u, 0x0010, 0x0001),
            new RunEntryDosToNt(0xc0130012u, 0x0005, 0x0001),
            new RunEntryDosToNt(0xc0150001u, 0x0008, 0x0001),
            new RunEntryDosToNt(0xc015000au, 0x0002, 0x0001),
            new RunEntryDosToNt(0xc015000eu, 0x0001, 0x0001),
            new RunEntryDosToNt(0xc01a0001u, 0x000b, 0x0001),
            new RunEntryDosToNt(0xc01a000du, 0x0022, 0x0001),
            new RunEntryDosToNt(0xc0980001u, 0x0002, 0x0001),
            new RunEntryDosToNt(0xc0980008u, 0x0001, 0x0001),
            new RunEntryDosToNt(0xffffffffu, 0x0001, 0x0001),
            new RunEntryDosToNt(0x0u, 0x0, 0x0),
        };

private static int RtlDosErrorToNtStatusMaybeInternal(uint dosErrorLow16, int candidate)
        {
            int last_err = unchecked((int)(dosErrorLow16 & 0xFFFFu));
            int index = -1;
            int number = 0;
            for (int i = 0; i < RtlpStatusTableDosToNt.Length; ++i)
            {
                if ((int)RtlpStatusTableDosToNt[i] == last_err)
                {
                    index = i;
                    if (number++ >= candidate)
                    {
                        break;
                    }
                }
            }
            if (number <= candidate)
            {
                return -1;
            }
            int baseIdx = 0;
            int status = -1;
            for (int i = 0; i < RtlpRunTableDosToNt.Length; ++i)
            {
                int next = baseIdx + RtlpRunTableDosToNt[i].RunLength * RtlpRunTableDosToNt[i].CodeSize;
                if (baseIdx <= index && index < next)
                {
                    int offset = (index - baseIdx) / RtlpRunTableDosToNt[i].CodeSize;
                    status = unchecked((int)(RtlpRunTableDosToNt[i].BaseCode + (uint)offset));
                    break;
                }
                baseIdx = next;
            }
            return status;
        }

        private static void TryAddNtStatusForDosError(uint dos, int status, System.Collections.Generic.HashSet<int> seen, System.Collections.Generic.List<int> outList)
        {
            if (status == -1) { return; }
            if (status == 0) { return; }
            uint rt = NativeMethods.RtlNtStatusToDosError(status);
            if (rt != dos) { return; }
            if (seen.Add(status)) { outList.Add(status); }
        }

        public static string FormatDosErrorToNtStatusBestEffort(uint dosErrorLow16)
        {
            uint dos = dosErrorLow16 & 0xFFFFu;
            var set = new System.Collections.Generic.HashSet<int>();
            var list = new System.Collections.Generic.List<int>();

            if (RtlDosErrorToNtStatusFn != null)
            {
                try { TryAddNtStatusForDosError(dos, RtlDosErrorToNtStatusFn(dos), set, list); } catch { }
            }

            for (int cand = 0; cand < 512; cand++)
            {
                int st = RtlDosErrorToNtStatusMaybeInternal(dos, cand);
                if (st == -1) { break; }
                TryAddNtStatusForDosError(dos, st, set, list);
            }

            var filtered = new System.Collections.Generic.List<int>();
            for (int i = 0; i < list.Count; i++)
            {
                uint u = unchecked((uint)list[i]);
                if ((u & 0xC0000000u) == 0xC0000000u)
                {
                    filtered.Add(list[i]);
                }
            }
            if (filtered.Count > 0)
            {
                list = filtered;
            }

            if (list.Count == 0)
            {
                return "(no NTSTATUS mapping found for this Win32 code)";
            }

            var sb = new StringBuilder();
            for (int i = 0; i < list.Count; i++)
            {
                if (i > 0) { sb.Append("; "); }
                uint u = unchecked((uint)list[i]);
                sb.AppendFormat(System.Globalization.CultureInfo.InvariantCulture, "0x{0:X8} ({1})", u, AsSignedInt32(u));
            }
            return sb.ToString();
        }
        public static uint HRESULT_FROM_WIN32(uint win32ErrorLow16)
        {
            return 0x80070000u | (win32ErrorLow16 & 0xFFFFu);
        }

        public static int AsSignedInt32(uint u)
        {
            return unchecked((int)u);
        }

        public static uint RtlNtStatusToDosErrorUInt(int ntStatus)
        {
            return NativeMethods.RtlNtStatusToDosError(ntStatus);
        }

        public static int RtlDosErrorToNtStatusInt(uint dosError)
        {
            if (RtlDosErrorToNtStatusFn == null)
            {
                return 0;
            }
            return RtlDosErrorToNtStatusFn(dosError);
        }

        public static bool IsRtlDosErrorToNtStatusAvailable
        {
            get { return RtlDosErrorToNtStatusFn != null; }
        }

        public static uint Low32BitsFromSignedValue(long value)
        {
            unchecked
            {
                return (uint)(value & 0xFFFFFFFFL);
            }
        }

        public static uint Low32BitsFromUnsignedValue(ulong value)
        {
            unchecked
            {
                return (uint)(value & 0xFFFFFFFFUL);
            }
        }

        public static uint Low16OfUInt32(uint value)
        {
            return value & 0xFFFFu;
        }

        public static string TryFormatWin32(uint code)
        {
            var sb = new StringBuilder(2048);
            uint len = NativeMethods.FormatMessage(
                NativeMethods.FORMAT_MESSAGE_FROM_SYSTEM | NativeMethods.FORMAT_MESSAGE_IGNORE_INSERTS,
                IntPtr.Zero,
                code,
                0,
                sb,
                (uint)sb.Capacity,
                IntPtr.Zero);
            if (len == 0)
            {
                return null;
            }
            return sb.ToString().TrimEnd();
        }

        public static string TryFormatNtStatus(uint ntStatus)
        {
            if (NtdllModule == IntPtr.Zero)
            {
                return null;
            }
            var sb = new StringBuilder(2048);
            uint len = NativeMethods.FormatMessage(
                NativeMethods.FORMAT_MESSAGE_FROM_HMODULE | NativeMethods.FORMAT_MESSAGE_IGNORE_INSERTS,
                NtdllModule,
                ntStatus,
                0,
                sb,
                (uint)sb.Capacity,
                IntPtr.Zero);
            if (len == 0)
            {
                return null;
            }
            return sb.ToString().TrimEnd();
        }

        public static string TryGetHResultMessage(int hr)
        {
            try
            {
                var ex = Marshal.GetExceptionForHR(hr);
                if (ex != null)
                {
                    return ex.Message.Trim();
                }
            }
            catch
            {
            }
            return null;
        }
    }
}
'@
}

