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

    /// <summary>
    /// Steam Stub DRM Unpacker (Variant #1)
    /// 
    /// Special thanks to Cyanic (aka Golem_x86) for his assistance.
    /// </summary>
    [SteamStubUnpacker(
        Author = "atom0s (thanks to Cyanic)", Name = "SteamStub Variant #1",
        Pattern = "53 51 52 56 57 55 8B EC 81 EC 00 10 00 00 BE")]
    public class SteamStubVariant1 : SteamStubUnpacker
    {
        /// <summary>
        /// Processes the given file in attempt to unpack the Steam Stub variant 1.
        /// </summary>
        /// <param name="file"></param>
        /// <returns></returns>
        public override bool Process(Pe32File file)
        {
            Program.Output("File is packed with SteamStub Variant #1!", ConsoleOutputType.Info);
            return false;
        }
    }
}