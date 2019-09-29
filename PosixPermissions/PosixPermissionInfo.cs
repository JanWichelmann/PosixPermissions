using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("PosixPermissions.Tests")]
namespace PosixPermissions
{
    /// <summary>
    /// Contains a combination of file permissions and a POSIX access control list, which can be applied to any file.
    /// </summary>
    public partial class PosixPermissionInfo
    {
        /// <summary>
        /// The UID of the file owner.
        /// </summary>
        private int _ownerId;

        /// <summary>
        /// <para>Gets or sets the UID of the file owner.</para>
        /// <para>If the UID is already present in the ACL, the associated permissions are copied to <see cref="OwnerPermissions"/>.</para>
        /// <para>The permissions of the former file owner are discarded.</para>
        /// </summary>
        public int OwnerId
        {
            get => _ownerId;
            set
            {
                // Remove the ACL entry, if there is any
                if(_aclUserPermissions.TryGetValue(value, out _ownerPermissions))
                    _aclUserPermissions.Remove(value);

                // Update ID
                _ownerId = value;
            }
        }

        /// <summary>
        /// The file permissions of the file owner.
        /// </summary>
        private FilePermissions _ownerPermissions;

        /// <summary>
        /// Gets or sets the file permissions of the file owner.
        /// </summary>
        public FilePermissions OwnerPermissions { get => _ownerPermissions; set => _ownerPermissions = value; }

        /// <summary>
        /// The GID of the file's associated group.
        /// </summary>
        private int _groupId;

        /// <summary>
        /// <para>Gets or sets the GID of the file's associated group.</para>
        /// <para>If the GID is already present in the ACL, the associated permissions are copied to <see cref="GroupPermissions"/>.</para>
        /// <para>The permissions of the former group are discarded.</para>
        /// </summary>
        public int GroupId
        {
            get => _groupId;
            set
            {
                // Remove the ACL entry, if there is any
                if(_aclGroupPermissions.TryGetValue(value, out _groupPermissions))
                    _aclGroupPermissions.Remove(value);

                // Update ID
                _groupId = value;
            }
        }

        /// <summary>
        /// The file permissions of the file's associated group.
        /// </summary>
        private FilePermissions _groupPermissions;

        /// <summary>
        /// Gets or sets the file permissions of the file's associated group.
        /// </summary>
        public FilePermissions GroupPermissions { get => _groupPermissions; set => _groupPermissions = value; }

        /// <summary>
        /// Gets or sets the file permissions of "others".
        /// </summary>
        public FilePermissions OtherPermissions { get; set; }

        /// <summary>
        /// The ACL user entries.
        /// </summary>
        private readonly Dictionary<int, FilePermissions> _aclUserPermissions = new Dictionary<int, FilePermissions>();

        /// <summary>
        /// The ACL group entries.
        /// </summary>
        private readonly Dictionary<int, FilePermissions> _aclGroupPermissions = new Dictionary<int, FilePermissions>();

        /// <summary>
        /// Creates a new <see cref="PosixPermissionInfo"/> object with an empty access control list for the given owner and group.
        /// </summary>
        /// <param name="nativeLibraryInterface">Object for native operations.</param>
        /// <param name="ownerId">The UID of the file's owner.</param>
        /// <param name="groupId">The GID of the file's group.</param>
        public PosixPermissionInfo(INativeLibraryInterface nativeLibraryInterface, int ownerId, int groupId)
        {
            // Initialize fields
            _nativeLibraryInterface = nativeLibraryInterface ?? throw new ArgumentNullException(nameof(nativeLibraryInterface));
            OwnerId = ownerId;
            OwnerPermissions = FilePermissions.None;
            GroupId = groupId;
            GroupPermissions = FilePermissions.None;
            OtherPermissions = FilePermissions.None;
        }

        /// <summary>
        /// Tries to retrieve the permissions for the given user.
        /// </summary>
        /// <param name="uid">The ID of the user to retrieve the permissions for.</param>
        /// <param name="filePermissions">Pointer to a variable to store the retrieved permissions.</param>
        /// <returns>A boolean indicating whether the user permission object could be retrieved (true) or not (false).</returns>
        public bool TryGetUserPermissions(int uid, out FilePermissions filePermissions)
        {
            // Try to retrieve permissions
            if(OwnerId == uid)
            {
                filePermissions = OwnerPermissions;
                return true;
            }
            return _aclUserPermissions.TryGetValue(uid, out filePermissions);
        }

        /// <summary>
        /// <para>Sets the permissions for the given user.</para>
        /// <para>If the user already has an entry in the ACL, it is updated with the new permissions.</para>
        /// <para>If the user ID matches the <see cref="OwnerId"/> property, the <see cref="OwnerPermissions"/> property is updated instead.</para>
        /// </summary>
        /// <param name="uid">The ID of the user to set the permissions for.</param>
        /// <param name="permissions">The permissions to set.</param>
        public void SetUserPermissions(int uid, FilePermissions permissions)
        {
            // Owner or ACL entry?
            if(OwnerId == uid)
                _ownerPermissions = permissions;
            else
                _aclUserPermissions[uid] = permissions;
        }

        /// <summary>
        /// <para>Sets the permissions for multiple users.</para>
        /// <para>If a particular user already has an entry in the ACL, it is updated with the new permissions.</para>
        /// <para>If a user ID matches the <see cref="OwnerId"/> property, the <see cref="OwnerPermissions"/> property is updated instead.</para>
        /// <para>If a user ID is assigned multiple times, the last one is taken. Note that this depends of the underlying implementation and thus might lead to undefined behavior.</para>
        /// </summary>
        /// <param name="permissions">A list of UID/<see cref="FilePermissions"/> combinations, which shall be copied into the ACL.</param>
        /// <exception cref="ArgumentNullException">Thrown when <see cref="permissions"/> is null.</exception>
        public void SetUserPermissions(IEnumerable<KeyValuePair<int, FilePermissions>> permissions)
        {
            // Parameter checks
            if(permissions == null)
                throw new ArgumentNullException(nameof(permissions));

            // Apply permissions
            foreach(var p in permissions)
                SetUserPermissions(p.Key, p.Value);
        }

        /// <summary>
        /// <para>Removes the ACL permission data of the given user.</para>
        /// <para>Note: This is _not_ equivalent to setting the permissions to <see cref="FilePermissions.None"/>; instead the user's ACL entry is removed.</para>
        /// <para>The owner's permissions cannot be removed.</para>
        /// </summary>
        /// <param name="uid">The ID of the user to remove from the ACL.</param>
        /// <exception cref="ArgumentException">Thrown when trying to remove the owner's permissions.</exception>
        public void RemoveUserPermissions(int uid)
        {
            // Parameter checks
            if(OwnerId == uid)
                throw new ArgumentException("The file owner's permissions cannot be deleted.");

            // Remove entry
            if(_aclUserPermissions.ContainsKey(uid))
                _aclUserPermissions.Remove(uid);
        }

        /// <summary>
        /// Tries to retrieve the permissions for the given group.
        /// </summary>
        /// <param name="gid">The ID of the group to retrieve the permissions for.</param>
        /// <param name="filePermissions">Pointer to a variable to store the retrieved permissions.</param>
        /// <returns>A boolean indicating whether the group permission object could be retrieved (true) or not (false).</returns>
        public bool TryGetGroupPermissions(int gid, out FilePermissions filePermissions)
        {
            // Try to retrieve permissions
            if(GroupId == gid)
            {
                filePermissions = GroupPermissions;
                return true;
            }
            return _aclGroupPermissions.TryGetValue(gid, out filePermissions);
        }

        /// <summary>
        /// <para>Sets the permissions for the given group.</para>
        /// <para>If the group already has an entry in the ACL, it is updated with the new permissions.</para>
        /// <para>If the group ID matches the <see cref="GroupId"/> property, the <see cref="GroupPermissions"/> property is updated instead.</para>
        /// </summary>
        /// <param name="gid">The ID of the group to set the permissions for.</param>
        /// <param name="permissions">The permissions to set.</param>
        public void SetGroupPermissions(int gid, FilePermissions permissions)
        {
            // File group or ACL entry?
            if(GroupId == gid)
                _groupPermissions = permissions;
            else
                _aclGroupPermissions[gid] = permissions;
        }

        /// <summary>
        /// <para>Sets the permissions for multiple groups.</para>
        /// <para>If a particular group already has an entry in the ACL, it is updated with the new permissions.</para>
        /// <para>If a group ID matches the <see cref="GroupId"/> property, the <see cref="GroupPermissions"/> property is updated instead.</para>
        /// <para>If a group ID is assigned multiple times, the last one is taken. Note that this depends of the underlying implementation and thus might lead to undefined behavior.</para>
        /// </summary>
        /// <param name="permissions">A list of GID/<see cref="FilePermissions"/> combinations, which shall be copied into the ACL.</param>
        /// <exception cref="ArgumentNullException">Thrown when <see cref="permissions"/> is null.</exception>
        public void SetGroupPermissions(IEnumerable<KeyValuePair<int, FilePermissions>> permissions)
        {
            // Parameter checks
            if(permissions == null)
                throw new ArgumentNullException(nameof(permissions));

            // Apply permissions
            foreach(var p in permissions)
                SetGroupPermissions(p.Key, p.Value);
        }

        /// <summary>
        /// <para>Removes the ACL permission data of the given group.</para>
        /// <para>Note: This is _not_ equivalent to setting the permissions to <see cref="FilePermissions.None"/>; instead the group's ACL entry is removed.</para>
        /// <para>The file group's (<see cref="GroupId"/>) permissions cannot be removed.</para>
        /// </summary>
        /// <param name="gid">The ID of the group to remove from the ACL.</param>
        /// <exception cref="ArgumentException">Thrown when trying to remove the file group's (<see cref="GroupId"/>) permissions.</exception>
        public void RemoveGroupPermissions(int gid)
        {
            // Parameter checks
            if(GroupId == gid)
                throw new ArgumentException("The file group's permissions cannot be deleted.");

            // Remove entry
            if(_aclGroupPermissions.ContainsKey(gid))
                _aclGroupPermissions.Remove(gid);
        }

        /// <summary>
        /// <para>Removes all ACL data.</para>
        /// <para>This is equivalent to applying a default ACL.</para>
        /// </summary>
        public void ClearAcls()
        {
            // Clear lists
            _aclUserPermissions.Clear();
            _aclGroupPermissions.Clear();
        }
    }
}
