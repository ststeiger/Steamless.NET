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
    public enum ConsoleOutputType
    {
        /// <summary>
        /// Console output used for general information. 
        /// 
        /// Uses a white foreground color.
        /// </summary>
        Info = 0,

        /// <summary>
        /// Console output used for warning information. 
        /// 
        /// Uses a yellow foreground color.
        /// </summary>
        Warning = 1,

        /// <summary>
        /// Console output used for error information. 
        /// 
        /// Uses a red foreground color.
        /// </summary>
        Error = 2,

        /// <summary>
        /// Console output used for success information. 
        /// 
        /// Uses a green foreground color.
        /// </summary>
        Success = 3,

        /// <summary>
        /// Console output used for custom information. 
        /// 
        /// Uses a custom foreground color.
        /// </summary>
        Custom = 4
    }
}