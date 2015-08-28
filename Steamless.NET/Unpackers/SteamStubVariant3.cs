/**
 * Steamless Steam DRM Remover
 * (c) 2015 atom0s [atom0s@live.com]
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see http://www.gnu.org/licenses/
 */

namespace Steamless.NET.Unpackers
{
    using Classes;
    using Extensions;
    using System;
    using System.IO;
    using System.Linq;
    using System.Runtime.InteropServices;
    using System.Security.Cryptography;

    /// <summary>
    /// Steam Stub DRM Unpacker (Variant #3)
    /// 
    /// Special thanks to Cyanic (aka Golem_x86) for his assistance.
    /// </summary>
    [SteamStubUnpacker(
        Author = "atom0s (thanks to Cyanic)", Name = "SteamStub Variant #3",
        Pattern = "E8 00 00 00 00 50 53 51 52 56 57 55 8B 44 24 1C 2D 05 00 00 00 8B CC 83 E4 F0 51 51 51 50")]
    public class SteamStubVariant3 : SteamStubUnpacker
    {
        /// <summary>
        /// SteamStub Variant 3 DRM Flags
        /// </summary>
        public enum DrmFlags
        {
            NoModuleVerification = 0x02,
            NoEncryption = 0x04,
            NoOwnershipCheck = 0x10,
            NoDebuggerCheck = 0x20,
            NoErrorDialog = 0x40
        }

        /// <summary>
        /// SteamStub Variant 3 DRM Header
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct SteamStub32Var3Header
        {
            public uint XorKey; // The base XOR key, if defined, to unpack the file with.
            public uint Signature; // 0xC0DEC0DE signature to validate this header is proper.
            public ulong ImageBase; // The base of the image that is protected.
            public uint AddressOfEntryPoint; // The entry point that is set from the DRM.
            public uint BindSectionOffset; // The starting offset to the bind section data. RVA(AddressOfEntryPoint - BindSectionOffset)
            public uint Unknown0000; // [Cyanic: This field is most likely the .bind code size.]
            public uint OriginalEntryPoint; // The original entry point of the binary before it was protected.
            public uint Unknown0001; // [Cyanic: This field is most likely an offset to a string table.]
            public uint PayloadSize; // The size of the payload data.
            public uint DRMPDLLOffset; // The offset to the SteamDRMP.dll file.
            public uint DRMPDLLSize; // The size of the SteamDRMP.dll file.
            public uint SteamAppId; // The Steam Application ID of this game.
            public uint Flags; // The DRM flags used while creating the protected executable.
            public uint BindSectionVirtualSize; // The bind section virtual size.
            public uint Unknown0002; // [Cyanic: This field is most likely a hash of some sort.]
            public uint TextSectionVirtualAddress; // The text section virtual address.
            public uint TextSectionRawSize; // The raw size of the text section.

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x20)]
            public byte[] AES_Key; // The AES encryption key.

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x10)]
            public byte[] AES_IV; // The AES encryption IV.

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x10)]
            public byte[] TextSectionStolenData; // The first 16 bytes of the .text section stolen.

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x04)]
            public uint[] EncryptionKeys; // Encryption keys used for decrypting SteamDRMP.dll file.

            public uint Unknown0003; // [Cyanic: This field is most likely used to flag if the file has Tls data or not.]
            public uint Unknown0004;
            public uint Unknown0005;
            public uint Unknown0006;
            public uint Unknown0007;
            public uint Unknown0008;
            public uint GetModuleHandleA_RVA; // The RVA to GetModuleHandleA.
            public uint GetModuleHandleW_RVA; // The RVA to GetModuleHandleW.
            public uint LoadLibraryA_RVA; // The RVA to LoadLibraryA.
            public uint LoadLibraryW_RVA; // The RVA to LoadLibraryW.
            public uint GetProcAddress_RVA; // The RVA to GetProcAddress.
            public uint Unknown0009;
            public uint Unknown0010;
            public uint Unknown0011;
        }

        /// <summary>
        /// Processes the given file in attempt to unpack the Steam Stub variant 3.
        /// </summary>
        /// <param name="file"></param>
        /// <returns></returns>
        public override bool Process(Pe32File file)
        {
            Program.Output("File is packed with SteamStub Variant #3!", ConsoleOutputType.Info);

            // Store the file object being processed..
            this.File = file;

            // Step #1 - Read the steam stub header.
            Program.Output("Info: Unpacker Stage #1", ConsoleOutputType.Custom, ConsoleColor.Magenta);
            if (!this.Step1())
                return false;

            // Step #2 - Read the payload.
            Program.Output("Info: Unpacker Stage #2", ConsoleOutputType.Custom, ConsoleColor.Magenta);
            if (!this.Step2())
                return false;

            // Step #3 - Read the SteamDRMP.dll file.
            Program.Output("Info: Unpacker Stage #3", ConsoleOutputType.Custom, ConsoleColor.Magenta);
            if (!this.Step3())
                return false;

            // Step #4 - Read the .text section.
            Program.Output("Info: Unpacker Stage #4", ConsoleOutputType.Custom, ConsoleColor.Magenta);
            if (!this.Step4())
                return false;

            // Step #5 - Save the file.
            Program.Output("Info: Unpacker Stage #5", ConsoleOutputType.Custom, ConsoleColor.Magenta);
            if (!this.Step5())
                return false;

            Program.Output("Processed the file successfully!", ConsoleOutputType.Success);

            return true;
        }

        /// <summary>
        /// Step #1
        /// 
        /// Reads, decodes and validates the Steam DRM header.
        /// </summary>
        /// <returns></returns>
        private bool Step1()
        {
            // Obtain the entry point file offset..
            var fileOffset = this.File.GetFileOffsetFromRva(this.File.NtHeaders.OptionalHeader.AddressOfEntryPoint);

            // Read the raw header data from the file data..
            var headerData = new byte[Marshal.SizeOf(typeof(SteamStub32Var3Header))];
            Array.Copy(this.File.FileData, (int)(fileOffset - (uint)Marshal.SizeOf(typeof(SteamStub32Var3Header))), headerData, 0, Marshal.SizeOf(typeof(SteamStub32Var3Header)));

            // Decode and obtain the steam stub header..
            this.XorKey = SteamXor(ref headerData, (uint)Marshal.SizeOf(typeof(SteamStub32Var3Header)));
            this.StubHeader = Helpers.GetStructure<SteamStub32Var3Header>(headerData);

            // Validate the header signature..
            return this.StubHeader.Signature == 0xC0DEC0DE;
        }

        /// <summary>
        /// Step #2
        /// 
        /// Reads, decodes, and processes the payload data.
        /// </summary>
        /// <returns></returns>
        private bool Step2()
        {
            // Obtain the payload address and size..
            var payloadAddr = this.File.GetFileOffsetFromRva(this.File.NtHeaders.OptionalHeader.AddressOfEntryPoint - this.StubHeader.BindSectionOffset);
            var payloadSize = (this.StubHeader.PayloadSize + 0x0F) & 0xFFFFFFF0;

            // Do nothing if we have no payload to process..
            if (payloadSize == 0)
                return true;

            // Obtain and decode the payload..
            var payload = new byte[payloadSize];
            Array.Copy(this.File.FileData, payloadAddr, payload, 0, payloadSize);
            this.XorKey = SteamXor(ref payload, payloadSize, this.XorKey);

            // TODO: Do something with the payload here..

            return true;
        }

        /// <summary>
        /// Step #3
        /// 
        /// Reads, decodes, and dumps the SteamDRMP.dll file.
        /// </summary>
        /// <returns></returns>
        private bool Step3()
        {
            // Ensure we have a file to process..
            if (this.StubHeader.DRMPDLLSize == 0)
                return true;

            try
            {
                // Obtain the SteamDRMP.dll file address and data..
                var drmpAddr = this.File.GetFileOffsetFromRva(this.File.NtHeaders.OptionalHeader.AddressOfEntryPoint - this.StubHeader.BindSectionOffset + this.StubHeader.DRMPDLLOffset);
                var drmpData = new byte[this.StubHeader.DRMPDLLSize];
                Array.Copy(this.File.FileData, drmpAddr, drmpData, 0, drmpData.Length);

                // Decrypt the data (XTea Decryption)..
                SteamDrmpDecryptPass1(ref drmpData, this.StubHeader.DRMPDLLSize, this.StubHeader.EncryptionKeys);

                // Obtain the path of the current file..
                var basePath = Path.GetDirectoryName(this.File.FilePath);
                if (string.IsNullOrEmpty(basePath))
                    return false;

                // Attempt to save the SteamDRMP.dll file..
                var path = Path.Combine(basePath, "SteamDRMP.dll");
                System.IO.File.WriteAllBytes(path, drmpData);

                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Step #4
        /// 
        /// Read, decode, and process the text section.
        /// </summary>
        /// <returns></returns>
        private bool Step4()
        {
            // Do nothing if we are not encrypted..
            if ((this.StubHeader.Flags & (uint)DrmFlags.NoEncryption) == (uint)DrmFlags.NoEncryption)
                return true;

            // Ensure the .text section exists..
            if (!this.File.HasSection(".text"))
                return false;

            // Obtain the .text section..
            var textSection = this.File.GetSection(".text");

            try
            {
                // Obtain the .text section data..
                var textSectionData = new byte[textSection.SizeOfRawData + this.StubHeader.TextSectionStolenData.Length];
                Array.Copy(this.StubHeader.TextSectionStolenData, 0, textSectionData, 0, this.StubHeader.TextSectionStolenData.Length);
                Array.Copy(this.File.FileData, this.File.GetFileOffsetFromRva(textSection.VirtualAddress), textSectionData, this.StubHeader.TextSectionStolenData.Length, textSection.SizeOfRawData);

                // Create the AES decryption class..
                var aes = new AesHelper(this.StubHeader.AES_Key, this.StubHeader.AES_IV);
                aes.RebuildIv(this.StubHeader.AES_IV);
                var data = aes.Decrypt(textSectionData, CipherMode.CBC, PaddingMode.None);
                if (data == null)
                    return false;

                // Set the override section data..
                this.TextSectionData = textSectionData;

                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Step #5
        /// 
        /// Save the unpacked file.
        /// </summary>
        /// <returns></returns>
        private bool Step5()
        {
            FileStream fStream = null;
            byte[] overlayData = null;

            try
            {
                // Determine if the file has any overlay data..
                var lastSection = this.File.Sections.Last();
                var fileSize = lastSection.SizeOfRawData + lastSection.PointerToRawData;

                if (fileSize < this.File.FileData.Length)
                {
                    // Overlay exists, copy it..
                    overlayData = new byte[this.File.FileData.Length - fileSize];
                    Array.Copy(this.File.FileData, fileSize, overlayData, 0, this.File.FileData.Length - fileSize);
                }
            }
            catch
            {
                return false;
            }

            try
            {
                // Open the unpacked file for writing..
                var unpackedPath = this.File.FilePath + ".unpacked.exe";
                fStream = new FileStream(unpackedPath, FileMode.Create, FileAccess.ReadWrite);

                // Write the dos header back to the file..
                fStream.WriteBytes(Helpers.GetStructureBytes(this.File.DosHeader));

                // Write the dos stub back to the file if it exists..
                if (this.File.DosStubSize > 0)
                    fStream.WriteBytes(this.File.DosStubData);

                // Determine if we should remove the .bind section..
                if (!Program.HasArgument("--keepbind"))
                {
                    // Remove the .bind section from the file..
                    this.File.Sections.Remove(this.File.GetSection(".bind"));
                }

                // Rebuild the NT headers of the file..
                var ntHeaders = this.File.NtHeaders;
                var lastSection = this.File.Sections[this.File.Sections.Count - 1];
                if (!Program.HasArgument("--keepbind"))
                    ntHeaders.FileHeader.NumberOfSections--;
                ntHeaders.OptionalHeader.AddressOfEntryPoint = this.StubHeader.OriginalEntryPoint;
                ntHeaders.OptionalHeader.SizeOfImage = lastSection.VirtualAddress + lastSection.VirtualSize;

                // Write the Nt headers to the file..
                fStream.WriteBytes(Helpers.GetStructureBytes(ntHeaders));

                // Write the sections to the file..
                foreach (var s in this.File.Sections)
                {
                    // Obtain the sections data from the original file..
                    var sectionData = new byte[s.SizeOfRawData];
                    Array.Copy(this.File.FileData, this.File.GetFileOffsetFromRva(s.VirtualAddress), sectionData, 0, s.SizeOfRawData);

                    // Write the section header to the file..
                    fStream.WriteBytes(Helpers.GetStructureBytes(s));

                    // Write the section data to the file..
                    var sectionOffset = fStream.Position;
                    fStream.Position = s.PointerToRawData;

                    // Determine if we should handle the text section differently..
                    if (string.Compare(s.SectionName, ".text", StringComparison.InvariantCultureIgnoreCase) == 0)
                        fStream.WriteBytes(this.TextSectionData ?? sectionData);
                    else
                        fStream.WriteBytes(sectionData);
                    
                    // Reset the file offset..
                    fStream.Position = sectionOffset;
                }

                // Skip to the end of the stream..
                fStream.Position = fStream.Length;

                // Write the overlay back to the file if it exists..
                if (overlayData != null)
                    fStream.WriteBytes(overlayData);

                return true;
            }
            catch
            {
                return false;
            }
            finally
            {
                fStream?.Dispose();
            }
        }

        /// <summary>
        /// Xor decrypts the given data starting with the given key, if any.
        /// 
        /// @note    If no key is given (0) then the first key is read from the first
        ///          4 bytes inside of the data given.
        /// </summary>
        /// <param name="data">The data to xor decode.</param>
        /// <param name="size">The size of the data to decode.</param>
        /// <param name="key">The starting xor key to decode with.</param>
        /// <returns></returns>
        private static uint SteamXor(ref byte[] data, uint size, uint key = 0)
        {
            var offset = (uint)0;

            // Read the first key as the base xor key if we had none given..
            if (key == 0)
            {
                offset += 4;
                key = BitConverter.ToUInt32(data, 0);
            }

            // Decode the data..
            for (var x = offset; x < size; x += 4)
            {
                var val = BitConverter.ToUInt32(data, (int)x);
                Array.Copy(BitConverter.GetBytes(val ^ key), 0, data, x, 4);

                key = val;
            }

            return key;
        }

        /// <summary>
        /// The second pass of decryption for the SteamDRMP.dll file.
        /// 
        /// @note    The encryption method here is known as XTEA.
        /// </summary>
        /// <param name="res">The result value buffer to write our returns to.</param>
        /// <param name="keys">The keys used for the decryption.</param>
        /// <param name="v1">The first value to decrypt from.</param>
        /// <param name="v2">The second value to decrypt from.</param>
        /// <param name="n">The number of passes to crypt the data with.</param>
        private static void SteamDrmpDecryptPass2(ref uint[] res, uint[] keys, uint v1, uint v2, uint n = 32)
        {
            const uint delta = 0x9E3779B9;
            const uint mask = 0xFFFFFFFF;
            var sum = (delta * n) & mask;

            for (var x = 0; x < n; x++)
            {
                v2 = (v2 - (((v1 << 4 ^ v1 >> 5) + v1) ^ (sum + keys[sum >> 11 & 3]))) & mask;
                sum = (sum - delta) & mask;
                v1 = (v1 - (((v2 << 4 ^ v2 >> 5) + v2) ^ (sum + keys[sum & 3]))) & mask;
            }

            res[0] = v1;
            res[1] = v2;
        }

        /// <summary>
        /// The first pass of the decryption for the SteamDRMP.dll file.
        /// 
        /// @note    The encryption method here is known as XTEA. It is modded to include
        ///          some basic xor'ing.
        /// </summary>
        /// <param name="data">The data to decrypt.</param>
        /// <param name="size">The size of the data to decrypt.</param>
        /// <param name="keys">The keys used for the decryption.</param>
        private static void SteamDrmpDecryptPass1(ref byte[] data, uint size, uint[] keys)
        {
            var v1 = (uint)0x55555555;
            var v2 = (uint)0x55555555;

            for (var x = 0; x < size; x += 8)
            {
                var d1 = BitConverter.ToUInt32(data, x + 0);
                var d2 = BitConverter.ToUInt32(data, x + 4);

                var res = new uint[2];
                SteamDrmpDecryptPass2(ref res, keys, d1, d2);

                Array.Copy(BitConverter.GetBytes(res[0] ^ v1), 0, data, x + 0, 4);
                Array.Copy(BitConverter.GetBytes(res[1] ^ v2), 0, data, x + 4, 4);

                v1 = d1;
                v2 = d2;
            }
        }

        /// <summary>
        /// Gets or sets the file being processed by this unpacker.
        /// </summary>
        public Pe32File File { get; set; }

        /// <summary>
        /// Gets or sets the current xor key.
        /// </summary>
        public uint XorKey { get; set; }

        /// <summary>
        /// Gets or sets the steam stub header.
        /// </summary>
        public SteamStub32Var3Header StubHeader { get; set; }

        /// <summary>
        /// Gets or sets the text section data.
        /// </summary>
        public byte[] TextSectionData { get; set; }
    }
}