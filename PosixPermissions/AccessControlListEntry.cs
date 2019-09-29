using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace PosixPermissions
{
    /// <summary>
    /// Contains one POSIX access control list entry.
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    public struct AccessControlListEntry
    {
        /// <summary>
        /// The entry tag type.
        /// </summary>
        public AccessControlListEntryTagTypes TagType;

        /// <summary>
        /// The entry tag qualifier (usually user or group ID).
        /// </summary>
        public int TagQualifier;

        /// <summary>
        /// The entry permissions field.
        /// </summary>
        public FilePermissions Permissions;
    }
}
