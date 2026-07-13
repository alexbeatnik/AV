// Tests for ClamAV database (.cvd) header parsing (src\MainForm.Updates.cs).
// A real CVD starts with a 512-byte colon-separated header:
//   ClamAV-VDB:<build date>:<version>:<sig count>:...
using System;
using System.IO;
using System.Text;
using AVUI;

namespace AVUI.Tests
{
    static class CvdHeaderTests
    {
        static byte[] Header(string s)
        {
            return Encoding.ASCII.GetBytes(s);
        }

        public static void TestParsesVersionField()
        {
            byte[] h = Header("ClamAV-VDB:21 Jan 2026 10-33 -0500:27710:2075164:63:...");
            Assert.Equal(27710L, MainForm.CvdVersionFromHeader(h, h.Length), "version field");
        }

        public static void TestParsesSignatureCountField()
        {
            byte[] h = Header("ClamAV-VDB:21 Jan 2026 10-33 -0500:27710:2075164:63:...");
            Assert.Equal(2075164L, MainForm.CvdFieldFromHeader(h, h.Length, 3), "signature count field");
        }

        public static void TestMissingFieldIndexReturnsZero()
        {
            byte[] h = Header("ClamAV-VDB:date:27710");
            Assert.Equal(0L, MainForm.CvdFieldFromHeader(h, h.Length, 3), "field index past the last part");
        }

        public static void TestGarbageReturnsZero()
        {
            byte[] h = Header("<html>404 not found</html>");
            Assert.Equal(0L, MainForm.CvdVersionFromHeader(h, h.Length), "an HTML error page is not a database");
        }

        public static void TestTooFewFieldsReturnsZero()
        {
            byte[] h = Header("ClamAV-VDB:only-date");
            Assert.Equal(0L, MainForm.CvdVersionFromHeader(h, h.Length), "missing version field");
        }

        public static void TestNonNumericVersionReturnsZero()
        {
            byte[] h = Header("ClamAV-VDB:date:not-a-number:rest");
            Assert.Equal(0L, MainForm.CvdVersionFromHeader(h, h.Length), "non-numeric version");
        }

        public static void TestEmptyBufferReturnsZero()
        {
            Assert.Equal(0L, MainForm.CvdVersionFromHeader(new byte[0], 0), "empty buffer");
        }

        public static void TestRespectsLengthArgument()
        {
            // the version sits past the declared length — must not be read
            byte[] h = Header("ClamAV-VDB:date:27710:rest");
            Assert.Equal(0L, MainForm.CvdVersionFromHeader(h, 12), "len cuts off before the version");
        }
    }

    static class LocalCvdTests
    {
        public static void TestReadsVersionFromFile()
        {
            using (var tmp = new TempDir())
            {
                string header = "ClamAV-VDB:21 Jan 2026 10-33 -0500:27710:2075164:63:X:Y:Z:builder:1700000000";
                var content = new byte[512 + 100]; // header block + some fake payload
                Encoding.ASCII.GetBytes(header).CopyTo(content, 0);
                File.WriteAllBytes(tmp.File("daily.cvd"), content);
                Assert.Equal(27710L, MainForm.LocalCvdVersion(tmp.File("daily.cvd")), "version from file header");
            }
        }

        public static void TestMissingFileReturnsZero()
        {
            using (var tmp = new TempDir())
                Assert.Equal(0L, MainForm.LocalCvdVersion(tmp.File("absent.cvd")), "missing file");
        }

        public static void TestCorruptFileReturnsZero()
        {
            using (var tmp = new TempDir())
            {
                File.WriteAllText(tmp.File("broken.cvd"), "this is not a cvd at all");
                Assert.Equal(0L, MainForm.LocalCvdVersion(tmp.File("broken.cvd")), "corrupt file");
            }
        }
    }
}
