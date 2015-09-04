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
    using SharpDisasm;
    using SharpDisasm.Udis86;
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Runtime.InteropServices;
    using System.Security.Cryptography;

    /// <summary>
    /// Steam Stub DRM Unpacker (Variant #2)
    /// 
    /// Special thanks to Cyanic (aka Golem_x86) for his assistance.
    /// </summary>
    [SteamStubUnpacker(
        Author = "atom0s (thanks to Cyanic)", Name = "SteamStub Variant #2",
        Pattern = "53 51 52 56 57 55 8B EC 81 EC 00 10 00 00 C7")]
    public class SteamStubVariant2 : SteamStubUnpacker
    {
        /// <summary>
        /// SteamStub Variant 2 DRM Flags
        /// </summary>
        public enum DrmFlags
        {
            NoModuleVerification = 0x02,
            NoEncryption = 0x04,
            NoOwnershipCheck = 0x10,
            NoDebuggerCheck = 0x20,
        }

        /// <summary>
        /// SteamStub Variant 2 DRM Header
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct SteamStub32Var2Header
        {
            public uint XorKey; // The base XOR key, if defined, to unpack the file with.
            public uint GetModuleHandleA_idata; // The address of GetModuleHandleA inside of the .idata section.
            public uint GetModuleHandleW_idata; // The address of GetModuleHandleW inside of the .idata section.
            public uint GetProcAddress_idata; // The address of GetProcAddress inside of the .idata section.
            public uint LoadLibraryA_idata; // The address of LoadLibraryA inside of the .idata section.
            public uint Unknown0000; // Unknown (Was 0 when testing. Possibly LoadLibraryW.)
            public uint BindSectionVirtualAddress; // The virtual address to the .bind section.
            public uint BindStartFunctionSize; // The size of the start function from the .bind section.
            public uint PayloadKeyMatch; // The key inside of the SteamDRMP.dll file that is matched to this structures data. (This matches the first 4 bytes of the payload data.)
            public uint PayloadDataVirtualAddress; // The virtual address to the payload data.
            public uint PayloadDataSize; // The size of the payload data.
            public uint SteamAppID; // The steam application id of the packed file.
            public uint Unknown0001; // Unknown

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x08)]
            public byte[] SteamAppIDString; // The SteamAppID of the packed file, in string format.

            public uint SteamDRMPDllVirtualAddress; // The offset inside of the payload data holding the virtual address to the SteamDRMP.dll file data.
            public uint SteamDRMPDllSize; // The offset inside of the payload data holding the size of the SteamDRMP.dll file data.
            public uint XTeaKeys; // The offset inside of the payload data holding the address to the Xtea keys to decrypt the SteamDRMP.dll file.

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x31C)]
            public byte[] StubData; // Misc stub data, such as strings, error messages, etc.
        }

        /// <summary>
        /// Processes the given file in attempt to unpack the Steam Stub variant 2.
        /// </summary>
        /// <param name="file"></param>
        /// <returns></returns>
        public override bool Process(Pe32File file)
        {
            Program.Output("File is packed with SteamStub Variant #2!", ConsoleOutputType.Info);

            // Store the file object being processed..
            this.File = file;

            // Step #1 - Read the steam stub header.
            Program.Output("Info: Unpacker Stage #1", ConsoleOutputType.Custom, ConsoleColor.Magenta);
            if (!this.Step1())
            {
                Program.Output("Failed to read SteamStub header from file.", ConsoleOutputType.Error);
                return false;
            }

            // Step #2 - Read the payload.
            Program.Output("Info: Unpacker Stage #2", ConsoleOutputType.Custom, ConsoleColor.Magenta);
            if (!this.Step2())
            {
                Program.Output("Failed to read payload from file.", ConsoleOutputType.Error);
                return false;
            }

            // Step #3 - Read the SteamDRMP.dll file.
            Program.Output("Info: Unpacker Stage #3", ConsoleOutputType.Custom, ConsoleColor.Magenta);
            if (!this.Step3())
            {
                Program.Output("Failed to read/dump SteamDRMP.dll from file.", ConsoleOutputType.Error);
                return false;
            }

            // Step #4 - Find needed offsets within the SteamDRMP.dll file..
            Program.Output("Info: Unpacker Stage #4", ConsoleOutputType.Custom, ConsoleColor.Magenta);
            if (!this.Step4())
            {
                Program.Output("Failed to obtain needed offsets from within SteamDRMP.dll.", ConsoleOutputType.Error);
                return false;
            }

            // Step #5 - Read the code section.
            Program.Output("Info: Unpacker Stage #5", ConsoleOutputType.Custom, ConsoleColor.Magenta);
            if (!this.Step5())
            {
                Program.Output("Failed to handle the code section of the file.", ConsoleOutputType.Error);
                return false;
            }

            // Step #6 - Save the file.
            Program.Output("Info: Unpacker Stage #6", ConsoleOutputType.Custom, ConsoleColor.Magenta);
            if (!this.Step6())
            {
                Program.Output("Failed to save unpacked file to disk.", ConsoleOutputType.Error);
                return false;
            }

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

            // Validate the DRM header..
            if (BitConverter.ToUInt32(this.File.FileData, (int)fileOffset - 4) != 0xC0DEC0DE)
                return false;

            int structOffset;
            int structSize;
            int structXorKey;

            // Disassemble the file to locate the needed information..
            if (!this.DisassembleFile(out structOffset, out structSize, out structXorKey))
                return false;

            // Read the raw header data from the file..
            var headerData = new byte[structSize];
            Array.Copy(this.File.FileData, this.File.GetFileOffsetFromRva((uint)structOffset), headerData, 0, structSize);

            // Decode and obtain the DRM header..
            this.XorKey = SteamXor(ref headerData, (uint)headerData.Length, (uint)structXorKey);
            this.StubHeader = Helpers.GetStructure<SteamStub32Var2Header>(headerData);

            return true;
        }

        /// <summary>
        /// Step #2
        /// 
        /// Reads, decodes, and processes the payload data.
        /// </summary>
        /// <returns></returns>
        private bool Step2()
        {
            // Obtain the payload data..
            var payloadAddr = this.File.GetFileOffsetFromRva(this.File.GetRvaFromVa(this.StubHeader.PayloadDataVirtualAddress));
            var payloadData = new byte[this.StubHeader.PayloadDataSize];
            Array.Copy(this.File.FileData, payloadAddr, payloadData, 0, this.StubHeader.PayloadDataSize);

            // Decode the payload data..
            this.XorKey = SteamXor(ref payloadData, this.StubHeader.PayloadDataSize, this.XorKey);
            this.PayloadData = payloadData;

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
            try
            {
                // Obtain the SteamDRMP.dll file data..
                var drmpAddr = this.File.GetFileOffsetFromRva(this.File.GetRvaFromVa(BitConverter.ToUInt32(this.PayloadData, (int)this.StubHeader.SteamDRMPDllVirtualAddress)));
                var drmpSize = BitConverter.ToUInt32(this.PayloadData, (int)this.StubHeader.SteamDRMPDllSize);
                var drmpData = new byte[drmpSize];
                Array.Copy(this.File.FileData, drmpAddr, drmpData, 0, drmpSize);

                // Decrypt the file data..
                var xteyKeys = new uint[(this.PayloadData.Length - this.StubHeader.XTeaKeys) / 4];
                for (var x = 0; x < (this.PayloadData.Length - this.StubHeader.XTeaKeys) / 4; x++)
                    xteyKeys[x] = BitConverter.ToUInt32(this.PayloadData, (int)this.StubHeader.XTeaKeys + (x * 4));
                SteamDrmpDecryptPass1(ref drmpData, drmpSize, xteyKeys);
                this.SteamDrmpData = drmpData;

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
        /// Finds needed offsets within the SteamDRMP.dll data.
        /// </summary>
        /// <returns></returns>
        private bool Step4()
        {
            // Scan for the needed data by a known pattern for the block of offset data..
            var drmpOffset = Helpers.FindPattern(this.SteamDrmpData, "8B ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 8D ?? ?? ?? ?? ?? 05");
            if (drmpOffset == 0)
                return false;

            // Copy the block of data from the SteamDRMP.dll data..
            var drmpOffsetData = new byte[1024];
            Array.Copy(this.SteamDrmpData, drmpOffset, drmpOffsetData, 0, 1024);

            // Obtain the offsets from the file data..
            var drmpOffsets = this.GetSteamDrmpOffsets(drmpOffsetData);
            if (drmpOffsets.Count != 8)
                return false;

            // Store the offsets..
            this.SteamDrmpOffsets = drmpOffsets;

            return true;
        }

        /// <summary>
        /// Step #5
        /// 
        /// Read, decode, and process the main code section.
        /// </summary>
        /// <returns></returns>
        private bool Step5()
        {
            byte[] codeSectionData;

            // Obtain the main code section (typically .text)..
            var mainSection = this.File.GetOwnerSection(this.File.GetRvaFromVa(BitConverter.ToUInt32(this.PayloadData.Skip(this.SteamDrmpOffsets[3]).Take(4).ToArray(), 0)));
            if (mainSection.PointerToRawData == 0 || mainSection.SizeOfRawData == 0)
                return false;

            // Save the code section for later use..
            this.CodeSection = mainSection;

            // Determine if we are using encryption on the section..
            var flags = BitConverter.ToUInt32(this.PayloadData.Skip(this.SteamDrmpOffsets[0]).Take(4).ToArray(), 0);
            if ((flags & (uint)DrmFlags.NoEncryption) == (uint)DrmFlags.NoEncryption)
            {
                // No encryption was used, just read the original data..
                codeSectionData = new byte[mainSection.SizeOfRawData];
                Array.Copy(this.File.FileData, this.File.GetFileOffsetFromRva(mainSection.VirtualAddress), codeSectionData, 0, mainSection.SizeOfRawData);
            }
            else
            {
                // Encryption was used, obtain the encryption information..
                var aesKey = this.PayloadData.Skip(this.SteamDrmpOffsets[5]).Take(32).ToArray();
                var aesIv = this.PayloadData.Skip(this.SteamDrmpOffsets[6]).Take(16).ToArray();
                var codeStolen = this.PayloadData.Skip(this.SteamDrmpOffsets[7]).Take(16).ToArray();

                // Restore the stolen data then read the rest of the section data..
                codeSectionData = new byte[mainSection.SizeOfRawData + codeStolen.Length];
                Array.Copy(codeStolen, 0, codeSectionData, 0, codeStolen.Length);
                Array.Copy(this.File.FileData, this.File.GetFileOffsetFromRva(mainSection.VirtualAddress), codeSectionData, codeStolen.Length, mainSection.SizeOfRawData);

                // Decrypt the code section..
                var aes = new AesHelper(aesKey, aesIv);
                aes.RebuildIv(aesIv);
                codeSectionData = aes.Decrypt(codeSectionData, CipherMode.CBC, PaddingMode.None);
            }

            // Store the section data..
            this.CodeSectionData = codeSectionData;

            return true;
        }

        /// <summary>
        /// Step #6
        /// 
        /// Save the unpacked file.
        /// </summary>
        /// <returns></returns>
        private bool Step6()
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

                // Write the dos stub back to the file, if it exists..
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
                var originalEntry = BitConverter.ToUInt32(this.PayloadData.Skip(this.SteamDrmpOffsets[2]).Take(4).ToArray(), 0);
                ntHeaders.OptionalHeader.AddressOfEntryPoint = this.File.GetRvaFromVa(originalEntry);
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

                    // Determine if this is the code section..
                    if (s.SizeOfRawData == this.CodeSection.SizeOfRawData && s.PointerToRawData == this.CodeSection.PointerToRawData)
                        fStream.WriteBytes(this.CodeSectionData ?? sectionData);
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
        /// Disassembles the current file to locate the needed .bind DRM information.
        /// </summary>
        /// <param name="offset"></param>
        /// <param name="size"></param>
        /// <param name="xorKey"></param>
        /// <returns></returns>
        private bool DisassembleFile(out int offset, out int size, out int xorKey)
        {
            // Determine the entry offset of the file..
            var entryOffset = this.File.GetFileOffsetFromRva(this.File.NtHeaders.OptionalHeader.AddressOfEntryPoint);

            // Prepare our needed variables..
            Disassembler disasm = null;
            var dataPointer = IntPtr.Zero;
            var structOffset = 0;
            var structSize = 0;
            var structXorKey = 0;

            try
            {
                // Copy the file data to memory for disassembling..
                dataPointer = Marshal.AllocHGlobal(this.File.FileData.Length);
                Marshal.Copy(this.File.FileData, 0, dataPointer, this.File.FileData.Length);

                // Create an offset pointer to our .bind function start..
                var startPointer = IntPtr.Add(dataPointer, (int)entryOffset);

                // Create the disassembler..
                Disassembler.Translator.IncludeAddress = true;
                Disassembler.Translator.IncludeBinary = true;

                disasm = new Disassembler(startPointer, 4096, ArchitectureMode.x86_32, entryOffset);

                // Disassemble our function..
                foreach (var inst in disasm.Disassemble().Where(inst => !inst.Error))
                {
                    // If all values are found, return successfully..
                    if (structOffset > 0 && structSize > 0 && structXorKey > 0)
                    {
                        offset = structOffset;
                        size = structSize;
                        xorKey = structXorKey;
                        return true;
                    }

                    // Looks for: mov dword ptr [value], immediate
                    if (inst.Mnemonic == ud_mnemonic_code.UD_Imov && inst.Operands[0].Type == ud_type.UD_OP_MEM && inst.Operands[1].Type == ud_type.UD_OP_IMM)
                    {
                        if (structOffset == 0)
                            structOffset = inst.Operands[1].LvalSDWord - (int)this.File.NtHeaders.OptionalHeader.ImageBase;
                        else
                            structXorKey = inst.Operands[1].LvalSDWord;
                    }

                    // Looks for: mov reg, immediate
                    if (inst.Mnemonic == ud_mnemonic_code.UD_Imov && inst.Operands[0].Type == ud_type.UD_OP_REG && inst.Operands[1].Type == ud_type.UD_OP_IMM)
                        structSize = inst.Operands[1].LvalSDWord * 4;
                }

                offset = size = xorKey = 0;
                return false;
            }
            catch
            {
                offset = size = xorKey = 0;
                return false;
            }
            finally
            {
                disasm?.Dispose();
                if (dataPointer != IntPtr.Zero)
                    Marshal.FreeHGlobal(dataPointer);
            }
        }

        /// <summary>
        /// Obtains the SteamDRMP.dll offsets needed to decode the .text section.
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        private List<int> GetSteamDrmpOffsets(byte[] data)
        {
            var offsets = new List<int>
                {
                    BitConverter.ToInt32(data, 2), // 0 Flags
                    BitConverter.ToInt32(data, 14), // 1 Steam App Id
                    BitConverter.ToInt32(data, 26), // 2 OEP
                    BitConverter.ToInt32(data, 38), // 3 .text Virtual Address
                    BitConverter.ToInt32(data, 50), // 4 .text Virtual Size (Encrypted Size)
                    BitConverter.ToInt32(data, 62) // 5 .text AES Key
                };

            var aesIvOffset = BitConverter.ToInt32(data, 67);
            offsets.Add(aesIvOffset); // 6 .text AES Iv
            offsets.Add(aesIvOffset + 16); // 7 .text Stolen Bytes
            return offsets;
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
        public SteamStub32Var2Header StubHeader { get; set; }

        /// <summary>
        /// Gets or sets the payload data.
        /// </summary>
        public byte[] PayloadData { get; set; }

        /// <summary>
        /// Gets or sets the SteamDRMP.dll data.
        /// </summary>
        public byte[] SteamDrmpData { get; set; }

        /// <summary>
        /// Gets or sets the list of SteamDRMP.dll offsets.
        /// </summary>
        public List<int> SteamDrmpOffsets { get; set; }

        /// <summary>
        /// Gets or sets the code section.
        /// </summary>
        public Structures.ImageSectionHeader CodeSection { get; set; }

        /// <summary>
        /// Gets or sets the text section data.
        /// </summary>
        public byte[] CodeSectionData { get; set; }
    }
}