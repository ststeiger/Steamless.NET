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

    public class SteamStubUnpackerAttribute : Attribute
    {
        /// <summary>
        /// Gets or sets the author of the unpacker.
        /// </summary>
        public string Author { get; set; }

        /// <summary>
        /// Gets or sets the name of the unpacker.
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// Gets or sets the pattern of the unpacker.
        /// </summary>
        public string Pattern { get; set; }
    }
}