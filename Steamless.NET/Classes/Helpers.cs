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
    using System.Linq;
    using System.Runtime.InteropServices;
    using static Structures;

    /// <summary>
    /// Helper functions used throughout Steamless.NET.
    /// </summary>
    public static class Helpers
    {
        /// <summary>
        /// Converts a byte array to the given structure type.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="data"></param>
        /// <param name="offset"></param>
        /// <returns></returns>
        public static T GetStructure<T>(byte[] data, int offset = 0)
        {
            var ptr = Marshal.AllocHGlobal(data.Length);
            Marshal.Copy(data, offset, ptr, data.Length - offset);
            var obj = (T)Marshal.PtrToStructure(ptr, typeof(T));
            Marshal.FreeHGlobal(ptr);

            return obj;
        }

        /// <summary>
        /// Converts the given object back to a byte array.
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="obj"></param>
        /// <returns></returns>
        public static byte[] GetStructureBytes<T>(T obj)
        {
            var size = Marshal.SizeOf(obj);
            var data = new byte[size];
            var ptr = Marshal.AllocHGlobal(size);
            Marshal.StructureToPtr(obj, ptr, true);
            Marshal.Copy(ptr, data, 0, size);
            Marshal.FreeHGlobal(ptr);
            return data;
        }

        /// <summary>
        /// Obtains a section from the given file information.
        /// </summary>
        /// <param name="rawData"></param>
        /// <param name="index"></param>
        /// <param name="dosHeader"></param>
        /// <param name="ntHeaders"></param>
        /// <returns></returns>
        public static ImageSectionHeader GetSection(byte[] rawData, int index, ImageDosHeader dosHeader, ImageNtHeaders32 ntHeaders)
        {
            var sectionSize = Marshal.SizeOf(typeof(ImageSectionHeader));
            var optionalHeaderOffset = Marshal.OffsetOf(typeof(ImageNtHeaders32), "OptionalHeader").ToInt32();
            var dataOffset = dosHeader.e_lfanew + optionalHeaderOffset + ntHeaders.FileHeader.SizeOfOptionalHeader;

            return GetStructure<ImageSectionHeader>(rawData, dataOffset + (index * sectionSize));
        }

        /// <summary>
        /// Scans the given data for the given pattern.
        /// 
        /// Notes:
        ///     Patterns are assumed to be 2 byte hex values with spaces.
        ///     Wildcards are represented by ??.
        /// </summary>
        /// <param name="data"></param>
        /// <param name="pattern"></param>
        /// <returns></returns>
        public static uint FindPattern(byte[] data, string pattern)
        {
            try
            {
                // Trim the pattern from extra whitespace..
                var trimPattern = pattern.Replace(" ", "").Trim();

                // Convert the pattern to a byte array..
                var patternMask = new List<bool>();
                var patternData = Enumerable.Range(0, trimPattern.Length).Where(x => x % 2 == 0)
                                            .Select(x =>
                                                {
                                                    var bt = trimPattern.Substring(x, 2);
                                                    patternMask.Add(!bt.Contains('?'));
                                                    return bt.Contains('?') ? (byte)0 : Convert.ToByte(bt, 16);
                                                }).ToArray();

                // Scan the given data for our pattern..
                for (var x = 0; x < data.Length; x++)
                {
                    if (!patternData.Where((t, y) => patternMask[y] && t != data[x + y]).Any())
                        return (uint)x;
                }

                return 0;
            }
            catch
            {
                return 0;
            }
        }
    }
}