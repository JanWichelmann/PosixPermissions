using System;
using System.Collections.Generic;
using System.Text;

namespace PosixPermissions
{
    /// <summary>
    /// Defines the different types of file permissions.
    /// </summary>
    [Flags]
    public enum FilePermissions : byte
    {
        /// <summary>
        /// No permissions.
        /// </summary>
        None = 0,

        /// <summary>
        /// The permission to execute (search) the given file (directory).
        /// </summary>
        Execute = 1,

        /// <summary>
        /// The permission to write into the given file.
        /// </summary>
        Write = 2,

        /// <summary>
        /// The permission to read (list) the given file (directory).
        /// </summary>
        Read = 4,

        /// <summary>
        /// Set user/group ID on execution (SUID/SGID bit). Only valid for "owner" and "group".
        /// </summary>
        SetId = 8,

        /// <summary>
        /// Restricted deletion in directories (sticky bit). Only valid for "owner".
        /// </summary>
        Sticky = 16
    }
}
