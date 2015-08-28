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
    using System.Security.Cryptography;

    /// <summary>
    /// Aes Decryption Helper Class
    /// </summary>
    public class AesHelper : IDisposable
    {
        /// <summary>
        /// Internal original key set by the user of this class.
        /// </summary>
        private readonly byte[] m_OriginalKey;

        /// <summary>
        /// Internal original iv set by the user of this class.
        /// </summary>
        private readonly byte[] m_OriginalIv;

        /// <summary>
        /// Internal AES crypto provider.
        /// </summary>
        private AesCryptoServiceProvider m_AesCryptoProvider;

        /// <summary>
        /// Default Constructor
        /// </summary>
        /// <param name="key"></param>
        /// <param name="iv"></param>
        /// <param name="mode"></param>
        /// <param name="padding"></param>
        public AesHelper(byte[] key, byte[] iv, CipherMode mode = CipherMode.ECB, PaddingMode padding = PaddingMode.None)
        {
            // Store the original key and iv..
            this.m_OriginalKey = key;
            this.m_OriginalIv = iv;

            // Create the AES crypto provider..
            this.m_AesCryptoProvider = new AesCryptoServiceProvider
                {
                    Key = key,
                    IV = iv,
                    Mode = mode,
                    Padding = padding
                };
        }

        /// <summary>
        /// Default Deconstructor
        /// </summary>
        ~AesHelper()
        {
            this.Dispose(false);
        }

        /// <summary>
        /// IDispose implementation.
        /// </summary>
        public void Dispose()
        {
            this.Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// IDispose implementation.
        /// </summary>
        /// <param name="disposing"></param>
        protected virtual void Dispose(bool disposing)
        {
            this.m_AesCryptoProvider?.Dispose();
            this.m_AesCryptoProvider = null;
        }

        /// <summary>
        /// Rebuilds the current iv (or the one given).
        /// </summary>
        /// <param name="iv"></param>
        /// <returns></returns>
        public bool RebuildIv(byte[] iv = null)
        {
            // Use the current iv if none is set..
            if (iv == null)
                iv = this.m_OriginalIv;

            try
            {
                using (var decryptor = this.m_AesCryptoProvider.CreateDecryptor())
                {
                    return decryptor.TransformBlock(iv, 0, iv.Length, this.m_OriginalIv, 0) > 0;
                }
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Decrypts the given data using the given mode and padding.
        /// </summary>
        /// <param name="data"></param>
        /// <param name="mode"></param>
        /// <param name="padding"></param>
        /// <returns></returns>
        public byte[] Decrypt(byte[] data, CipherMode mode, PaddingMode padding)
        {
            ICryptoTransform decryptor = null;
            MemoryStream mStream = null;
            CryptoStream cStream = null;

            try
            {
                // Update the mode and padding for the decryption..
                this.m_AesCryptoProvider.Mode = mode;
                this.m_AesCryptoProvider.Padding = padding;

                // Create the decryptor..
                decryptor = this.m_AesCryptoProvider.CreateDecryptor(this.m_OriginalKey, this.m_OriginalIv);

                // Create a memory stream for our data..
                mStream = new MemoryStream(data);

                // Create the crypto stream..
                cStream = new CryptoStream(mStream, decryptor, CryptoStreamMode.Read);

                // Decrypt the data..
                var totalBuffer = new List<byte>();
                var buffer = new byte[2048];
                while ((cStream.Read(buffer, 0, 2048)) > 0)
                    totalBuffer.AddRange(buffer);

                return totalBuffer.ToArray();
            }
            catch
            {
                return null;
            }
            finally
            {
                cStream?.Dispose();
                mStream?.Dispose();
                decryptor?.Dispose();
            }
        }
    }
}