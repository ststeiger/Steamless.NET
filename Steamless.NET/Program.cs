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

namespace Steamless.NET
{
    using Classes;
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Reflection;

    /// <summary>
    /// Main Application Class
    /// </summary>
    internal class Program
    {
        /// <summary>
        /// Application entry point.
        /// </summary>
        /// <param name="args"></param>
        private static void Main(string[] args)
        {
            // Print the application header..
            PrintHeader();

            // Parse the command line arguments..
            Arguments = new List<string>();
            Arguments.AddRange(Environment.GetCommandLineArgs());

            // Load the file and ensure it is valid..
            var file = new Pe32File(args[0]);
            if (!file.Parse() || file.IsFile64Bit() || !file.HasSection(".bind"))
                return;

            // Build a list of known unpackers within our local source..
            var unpackers = (from t in Assembly.GetExecutingAssembly().GetTypes()
                             from a in t.GetCustomAttributes(typeof(SteamStubUnpackerAttribute), false)
                             select t).ToList();

            // Print out the known unpackers we found..
            Output("Found the following unpackers (internal):", ConsoleOutputType.Info);
            foreach (var attr in unpackers.Select(unpacker => (SteamStubUnpackerAttribute)unpacker.GetCustomAttributes(typeof(SteamStubUnpackerAttribute)).FirstOrDefault()))
                Output($" >> Unpacker: {attr?.Name} - by: {attr?.Author}", ConsoleOutputType.Custom, ConsoleColor.Yellow);
            Console.WriteLine();

            // Process function to try and handle the file..
            Func<bool> processed = () =>
                {
                    // Obtain the .bind section data..
                    var bindSectionData = file.GetSectionData(".bind");

                    // Attempt to process the file..
                    return (from unpacker in unpackers
                            let attr = (SteamStubUnpackerAttribute)unpacker.GetCustomAttributes(typeof(SteamStubUnpackerAttribute)).FirstOrDefault()
                            where attr != null
                            where Helpers.FindPattern(bindSectionData, attr.Pattern) != 0
                            select Activator.CreateInstance(unpacker) as SteamStubUnpacker).Select(stubUnpacker => stubUnpacker.Process(file)).FirstOrDefault();
                };

            // Process the file..
            processed();

            // Pause the console so newbies can read the results..
            Console.WriteLine();
            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
        }

        /// <summary>
        /// Prints the header of this application.
        /// </summary>
        public static void PrintHeader()
        {
            var color = Console.ForegroundColor;

            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("==================================================================");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"\n>> Steamless.NET v{((AssemblyFileVersionAttribute)Attribute.GetCustomAttribute(Assembly.GetExecutingAssembly(), typeof(AssemblyFileVersionAttribute), false)).Version}\n");
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine("(c) 2015 atom0s [atom0s@live.com]");
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine("For more info, visit http://atom0s.com/");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("Special thanks to Cyanic for his research/help.");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("==================================================================\n");

            Console.ForegroundColor = color;
        }

        /// <summary>
        /// Outputs a message to the console with the given color.
        /// </summary>
        /// <param name="message"></param>
        /// <param name="outType"></param>
        /// <param name="color"></param>
        public static void Output(string message, ConsoleOutputType outType, ConsoleColor color = ConsoleColor.White)
        {
            // Store the original foreground color..
            var c = Console.ForegroundColor;

            // Prepare the new message build..
            var msg = "[!] ";

            // Set the color based on our message type..
            switch (outType)
            {
                case ConsoleOutputType.Info:
                    Console.ForegroundColor = ConsoleColor.White;
                    msg += "Info: " + message;
                    break;
                case ConsoleOutputType.Warning:
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    msg += "Warn: " + message;
                    break;
                case ConsoleOutputType.Error:
                    Console.ForegroundColor = ConsoleColor.Red;
                    msg += "Error: " + message;
                    break;
                case ConsoleOutputType.Success:
                    Console.ForegroundColor = ConsoleColor.Green;
                    msg += "Success: " + message;
                    break;
                case ConsoleOutputType.Custom:
                    Console.ForegroundColor = color;
                    msg += message;
                    break;
            }

            // Print the message..
            Console.WriteLine(msg);

            // Restore the foreground color..
            Console.ForegroundColor = c;
        }

        /// <summary>
        /// Determines if the application was passed the given argument.
        /// </summary>
        /// <param name="arg"></param>
        /// <returns></returns>
        public static bool HasArgument(string arg) => Arguments != null && Arguments.Contains(arg.ToLower());

        /// <summary>
        /// Gets or sets the list of arguments passed to this application on load.
        /// </summary>
        public static List<string> Arguments { get; set; }
    }
}