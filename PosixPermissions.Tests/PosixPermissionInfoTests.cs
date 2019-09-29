using System;
using System.Collections.Generic;
using Moq;
using Xunit;

namespace PosixPermissions.Tests
{
    public class PosixPermissionInfoTests
    {
        [Fact]
        public void UserPermissions()
        {
            // Always throw when used
            var mockNativeLibraryInterface = new Mock<INativeLibraryInterface>(MockBehavior.Strict);

            var posixPermissionInfo = new PosixPermissionInfo(mockNativeLibraryInterface.Object, 1000, 1);
            Assert.Equal(1000, posixPermissionInfo.OwnerId);
            Assert.True(posixPermissionInfo.TryGetUserPermissions(1000, out _));

            posixPermissionInfo.OwnerPermissions = FilePermissions.Read;
            Assert.Equal(FilePermissions.Read, posixPermissionInfo.OwnerPermissions);
            Assert.True(posixPermissionInfo.TryGetUserPermissions(1000, out FilePermissions ownerPermissions));
            Assert.Equal(FilePermissions.Read, ownerPermissions);

            posixPermissionInfo.SetUserPermissions(1000, FilePermissions.Write);
            Assert.True(posixPermissionInfo.TryGetUserPermissions(1000, out ownerPermissions));
            Assert.Equal(FilePermissions.Write, ownerPermissions);

            posixPermissionInfo.SetUserPermissions(2000, FilePermissions.Read);
            Assert.True(posixPermissionInfo.TryGetUserPermissions(2000, out FilePermissions userPermissions));
            Assert.Equal(FilePermissions.Read, userPermissions);

            Assert.Throws<ArgumentException>(() => posixPermissionInfo.RemoveUserPermissions(1000));

            Assert.False(posixPermissionInfo.TryGetUserPermissions(3000, out _));
            posixPermissionInfo.RemoveUserPermissions(3000); // Should not throw

            posixPermissionInfo.RemoveUserPermissions(2000);
            Assert.False(posixPermissionInfo.TryGetUserPermissions(2000, out _));

            Assert.Throws<ArgumentNullException>(() => posixPermissionInfo.SetUserPermissions(null));

            posixPermissionInfo.SetUserPermissions(new[] { new KeyValuePair<int, FilePermissions>(4000, FilePermissions.Execute) });
            posixPermissionInfo.OwnerId = 4000;
            Assert.Equal(FilePermissions.Execute, posixPermissionInfo.OwnerPermissions);

            Assert.False(posixPermissionInfo.TryGetUserPermissions(1000, out _));
        }

        [Fact]
        public void GroupPermissions()
        {
            // Always throw when used
            var mockNativeLibraryInterface = new Mock<INativeLibraryInterface>(MockBehavior.Strict);

            var posixPermissionInfo = new PosixPermissionInfo(mockNativeLibraryInterface.Object, 1, 1000);
            Assert.Equal(1000, posixPermissionInfo.GroupId);
            Assert.True(posixPermissionInfo.TryGetGroupPermissions(1000, out _));

            posixPermissionInfo.GroupPermissions = FilePermissions.Read;
            Assert.Equal(FilePermissions.Read, posixPermissionInfo.GroupPermissions);
            Assert.True(posixPermissionInfo.TryGetGroupPermissions(1000, out FilePermissions ownerPermissions));
            Assert.Equal(FilePermissions.Read, ownerPermissions);

            posixPermissionInfo.SetGroupPermissions(1000, FilePermissions.Write);
            Assert.True(posixPermissionInfo.TryGetGroupPermissions(1000, out ownerPermissions));
            Assert.Equal(FilePermissions.Write, ownerPermissions);

            posixPermissionInfo.SetGroupPermissions(2000, FilePermissions.Read);
            Assert.True(posixPermissionInfo.TryGetGroupPermissions(2000, out FilePermissions userPermissions));
            Assert.Equal(FilePermissions.Read, userPermissions);

            Assert.Throws<ArgumentException>(() => posixPermissionInfo.RemoveGroupPermissions(1000));

            Assert.False(posixPermissionInfo.TryGetGroupPermissions(3000, out _));
            posixPermissionInfo.RemoveGroupPermissions(3000); // Should not throw

            posixPermissionInfo.RemoveGroupPermissions(2000);
            Assert.False(posixPermissionInfo.TryGetGroupPermissions(2000, out _));

            Assert.Throws<ArgumentNullException>(() => posixPermissionInfo.SetGroupPermissions(null));

            posixPermissionInfo.SetGroupPermissions(new[] { new KeyValuePair<int, FilePermissions>(4000, FilePermissions.Execute) });
            posixPermissionInfo.GroupId = 4000;
            Assert.Equal(FilePermissions.Execute, posixPermissionInfo.GroupPermissions);

            Assert.False(posixPermissionInfo.TryGetGroupPermissions(1000, out _));
        }

        [Fact]
        public void OtherPermissions()
        {
            // Always throw when used
            var mockNativeLibraryInterface = new Mock<INativeLibraryInterface>(MockBehavior.Strict);

            var posixPermissionInfo = new PosixPermissionInfo(mockNativeLibraryInterface.Object, 1, 2);
            posixPermissionInfo.OtherPermissions = FilePermissions.Read;
            Assert.Equal(FilePermissions.Read, posixPermissionInfo.OtherPermissions);
        }

        [Fact]
        public void FromNative()
        {
            var mockNativeLibraryInterface = new Mock<INativeLibraryInterface>(MockBehavior.Strict);
            FilePermissions r = FilePermissions.Read;
            FilePermissions rw = FilePermissions.Read | FilePermissions.Write;
            FilePermissions rwx = FilePermissions.Read | FilePermissions.Write | FilePermissions.Execute;
            AccessControlListEntry[] acl =
            {
                new AccessControlListEntry { TagType = AccessControlListEntryTagTypes.UserObj, TagQualifier = 1000, Permissions = rwx },
                new AccessControlListEntry { TagType = AccessControlListEntryTagTypes.GroupObj, TagQualifier = 1000, Permissions = rw },
                new AccessControlListEntry { TagType = AccessControlListEntryTagTypes.Other, TagQualifier = -1, Permissions = r },
                new AccessControlListEntry { TagType = AccessControlListEntryTagTypes.User, TagQualifier = 2000, Permissions = rw },
                new AccessControlListEntry { TagType = AccessControlListEntryTagTypes.User, TagQualifier = 3000, Permissions = r },
                new AccessControlListEntry { TagType = AccessControlListEntryTagTypes.Group, TagQualifier = 2000, Permissions = rw },
                new AccessControlListEntry { TagType = AccessControlListEntryTagTypes.Group, TagQualifier = 3000, Permissions = r },
                new AccessControlListEntry { TagType = AccessControlListEntryTagTypes.Mask, TagQualifier = -1, Permissions = rw }
            };
            NativePermissionDataContainer dataContainer = new NativePermissionDataContainer
            {
                AclSize = acl.Length,
                OwnerId = 1000,
                GroupId = 1000,
                OwnerPermissions = rwx,
                GroupPermissions = rw,
                OtherPermissions = r
            };
            mockNativeLibraryInterface.Setup(obj => obj.GetPermissionData("file", 0, out dataContainer)).Returns(acl);

            var posixPermissionInfo = new PosixPermissionInfo(mockNativeLibraryInterface.Object, "file", 0);

            Assert.Equal(1000, posixPermissionInfo.OwnerId);
            Assert.Equal(rwx, posixPermissionInfo.OwnerPermissions);
            Assert.True(posixPermissionInfo.TryGetUserPermissions(2000, out var permissionsUser2000));
            Assert.Equal(rw, permissionsUser2000);
            Assert.True(posixPermissionInfo.TryGetUserPermissions(3000, out var permissionsUser3000));
            Assert.Equal(r, permissionsUser3000);

            Assert.Equal(1000, posixPermissionInfo.GroupId);
            Assert.Equal(rw, posixPermissionInfo.GroupPermissions);
            Assert.True(posixPermissionInfo.TryGetGroupPermissions(2000, out var permissionsGroup2000));
            Assert.Equal(rw, permissionsGroup2000);
            Assert.True(posixPermissionInfo.TryGetGroupPermissions(3000, out var permissionsGroup3000));
            Assert.Equal(r, permissionsGroup3000);

            Assert.Equal(r, posixPermissionInfo.OtherPermissions);
        }

        private delegate void SetPermissionDataCallback(string fileName, int setDefaultAcl, ref NativePermissionDataContainer dataContainer, AccessControlListEntry[] acl);

        [Fact]
        public void ToNative()
        {
            var mockNativeLibraryInterface = new Mock<INativeLibraryInterface>(MockBehavior.Strict);
            AccessControlListEntry[] acl = null;
            NativePermissionDataContainer dataContainer = default;
            mockNativeLibraryInterface.Setup(obj => obj.SetPermissionData("file", 0, ref It.Ref<NativePermissionDataContainer>.IsAny, It.IsAny<AccessControlListEntry[]>()))
                .Callback(new SetPermissionDataCallback((string fileNameParam, int setDefaultAclParam, ref NativePermissionDataContainer dataContainerParam, AccessControlListEntry[] aclParam) =>
                    {
                        dataContainer = dataContainerParam;
                        acl = aclParam;
                    }));

            FilePermissions r = FilePermissions.Read;
            FilePermissions rw = FilePermissions.Read | FilePermissions.Write;
            FilePermissions rwx = FilePermissions.Read | FilePermissions.Write | FilePermissions.Execute;

            var posixPermissionInfo = new PosixPermissionInfo(mockNativeLibraryInterface.Object, 1000, 1000);
            posixPermissionInfo.OwnerPermissions = rwx;
            posixPermissionInfo.GroupPermissions = rw;
            posixPermissionInfo.OtherPermissions = r;

            posixPermissionInfo.SetUserPermissions(2000, rw);
            posixPermissionInfo.SetUserPermissions(3000, r);

            posixPermissionInfo.SetGroupPermissions(2000, r); // Only "r" to test whether mask includes owning group
            posixPermissionInfo.SetGroupPermissions(3000, r);

            posixPermissionInfo.ApplyPermissions("file", false);

            Assert.NotNull(acl);

            Assert.Equal(1000, dataContainer.OwnerId);
            Assert.Equal(1000, dataContainer.GroupId);

            Assert.Equal(rwx, dataContainer.OwnerPermissions);
            Assert.Equal(rw, dataContainer.GroupPermissions);
            Assert.Equal(r, dataContainer.OtherPermissions);

            void CheckAclEntry3(int i, AccessControlListEntryTagTypes tagType, int tagQualifier, FilePermissions permissions)
            {
                Assert.Equal(tagType, acl[i].TagType);
                Assert.Equal(tagQualifier, acl[i].TagQualifier);
                Assert.Equal(permissions, acl[i].Permissions);
            }
            void CheckAclEntry2(int i, AccessControlListEntryTagTypes tagType, FilePermissions permissions)
            {
                Assert.Equal(tagType, acl[i].TagType);
                Assert.Equal(permissions, acl[i].Permissions);
            }

            Assert.Equal(8, acl.Length);

            CheckAclEntry3(0, AccessControlListEntryTagTypes.UserObj, 1000, rwx);
            CheckAclEntry3(1, AccessControlListEntryTagTypes.GroupObj, 1000, rw);
            CheckAclEntry2(2, AccessControlListEntryTagTypes.Other, r);
            CheckAclEntry3(3, AccessControlListEntryTagTypes.User, 2000, rw);
            CheckAclEntry3(4, AccessControlListEntryTagTypes.User, 3000, r);
            CheckAclEntry3(5, AccessControlListEntryTagTypes.Group, 2000, r);
            CheckAclEntry3(6, AccessControlListEntryTagTypes.Group, 3000, r);
            CheckAclEntry2(7, AccessControlListEntryTagTypes.Mask, rw);
        }
    }
}
