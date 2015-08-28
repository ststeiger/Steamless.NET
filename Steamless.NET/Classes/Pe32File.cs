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

namespace Steamless.NET.Classes
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Runtime.InteropServices;
    using static Structures;

    /// <summary>
    /// Portable Executable (32bit) .NET Class
    /// </summary>
    public class Pe32File
    {
        /// <summary>
        /// Default Constructor
        /// </summary>
        public Pe32File()
        {
        }

        /// <summary>
        /// Overloaded Constructor
        /// </summary>
        /// <param name="file"></param>
        public Pe32File(string file)
        {
            this.FilePath = file;
        }

        /// <summary>
        /// Parses the given PE file.
        /// </summary>
        /// <param name="file"></param>
        /// <returns></returns>
        public bool Parse(string file = null)
        {
            // Prepare the class variables for usage..
            this.Sections = new List<ImageSectionHeader>();
            this.DosStubSize = 0;
            this.DosStubOffset = 0;
            this.DosStubData = null;

            // Set the file path if it was given..
            if (file != null)
                this.FilePath = file;

            // Ensure the file exists..
            if (string.IsNullOrEmpty(this.FilePath) || !File.Exists(this.FilePath))
                return false;

            // Read the files raw data..
            this.FileData = File.ReadAllBytes(this.FilePath);

            // Some simple sanity checks..
            if (this.FileData.Length < (Marshal.SizeOf(typeof(ImageDosHeader)) + Marshal.SizeOf(typeof(ImageNtHeaders32))))
                return false;

            // Read the file headers..
            this.DosHeader = Helpers.GetStructure<ImageDosHeader>(this.FileData);
            this.NtHeaders = Helpers.GetStructure<ImageNtHeaders32>(this.FileData, this.DosHeader.e_lfanew);

            // Ensure the file headers are valid..
            if (!this.DosHeader.IsValid || !this.NtHeaders.IsValid)
                return false;

            // Store the dos stub if one exists..
            this.DosStubSize = (uint)(this.DosHeader.e_lfanew - Marshal.SizeOf(typeof(ImageDosHeader)));
            if (this.DosStubSize > 0)
            {
                this.DosStubOffset = (uint)Marshal.SizeOf(typeof(ImageDosHeader));
                this.DosStubData = new byte[this.DosStubSize];
                Array.Copy(this.FileData, this.DosStubOffset, this.DosStubData, 0, this.DosStubSize);
            }

            // Obtain the file sections..
            for (var x = 0; x < this.NtHeaders.FileHeader.NumberOfSections; x++)
            {
                var section = Helpers.GetSection(this.FileData, x, this.DosHeader, this.NtHeaders);
                this.Sections.Add(section);
            }

            return true;
        }

        /// <summary>
        /// Determines if the current pe file is 64bit.
        /// </summary>
        /// <returns></returns>
        public bool IsFile64Bit()
        {
            return (this.NtHeaders.FileHeader.Machine & (uint)MachineType.X64) == (uint)MachineType.X64;
        }

        /// <summary>
        /// Determines if the file has a given section by its name.
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        public bool HasSection(string name)
        {
            return this.Sections.Any(s => string.Compare(s.SectionName, name, StringComparison.InvariantCultureIgnoreCase) == 0);
        }

        /// <summary>
        /// Obtains a section by its name.
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        public ImageSectionHeader GetSection(string name)
        {
            return this.Sections.FirstOrDefault(s => string.Compare(s.SectionName, name, StringComparison.InvariantCultureIgnoreCase) == 0);
        }

        /// <summary>
        /// Obtains the owner section of the given rva.
        /// </summary>
        /// <param name="rva"></param>
        /// <returns></returns>
        public ImageSectionHeader GetOwnerSection(uint rva)
        {
            foreach (var s in this.Sections)
            {
                // Obtain the section size..
                var size = s.VirtualSize;
                if (size == 0)
                    size = s.SizeOfRawData;

                // Check if we are within the rva..
                if ((rva >= s.VirtualAddress) && (rva < s.VirtualAddress + size))
                    return s;
            }

            return default(ImageSectionHeader);
        }

        /// <summary>
        /// Obtains a sections data by its name.
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        public byte[] GetSectionData(string name)
        {
            var section = this.GetSection(name);

            var sectionData = new byte[section.SizeOfRawData];
            Array.Copy(this.FileData, this.GetFileOffsetFromRva(section.VirtualAddress), sectionData, 0, section.SizeOfRawData);

            return sectionData;
        }

        /// <summary>
        /// Obtains the relative virtual address from the given virtual address.
        /// </summary>
        /// <param name="va"></param>
        /// <returns></returns>
        public uint GetRvaFromVa(uint va)
        {
            return va - this.NtHeaders.OptionalHeader.ImageBase;
        }

        /// <summary>
        /// Obtains the file offset from the given relative virtual address.
        /// </summary>
        /// <param name="rva"></param>
        /// <returns></returns>
        public uint GetFileOffsetFromRva(uint rva)
        {
            var section = this.GetOwnerSection(rva);
            return (rva - (section.VirtualAddress - section.PointerToRawData));
        }

        /// <summary>
        /// Gets the aligment of the given value.
        /// </summary>
        /// <param name="val"></param>
        /// <param name="align"></param>
        /// <returns></returns>
        public uint GetAlignment(uint val, uint align)
        {
            return (((val + align - 1) / align) * align);
        }

        /// <summary>
        /// Gets or sets the path to the file being processed.
        /// </summary>
        public string FilePath { get; set; }

        /// <summary>
        /// Gets or sets the raw file data of the file being processed.
        /// </summary>
        public byte[] FileData { get; set; }

        /// <summary>
        /// Gets or sets the dos header.
        /// </summary>
        public ImageDosHeader DosHeader { get; set; }

        /// <summary>
        /// Gets or sets the NT headers.
        /// </summary>
        public ImageNtHeaders32 NtHeaders { get; set; }

        /// <summary>
        /// Gets or sets the dos stub size (if present).
        /// </summary>
        public uint DosStubSize { get; set; }

        /// <summary>
        /// Gets or sets the dos stub offset (if present).
        /// </summary>
        public uint DosStubOffset { get; set; }

        /// <summary>
        /// Gets or sets the dos stub data (if present).
        /// </summary>
        public byte[] DosStubData { get; set; }

        /// <summary>
        /// Gets or sets the list of file sections.
        /// </summary>
        public List<ImageSectionHeader> Sections { get; set; }
    }
}