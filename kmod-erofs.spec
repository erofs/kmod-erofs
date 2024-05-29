%define kmod_name		erofs
%define kmod_driver_version	1
%define kmod_kernel_version	3.10.0-123.el7
%define kmod_headers_version	%(rpm -qa kernel-devel | sed 's/^kernel-devel-//' | head -n1)

%define erofs_kcfgs CONFIG_EROFS_FS_XATTR=y CONFIG_EROFS_FS_SECURITY=y CONFIG_EROFS_FS_POSIX_ACL=y

Name:		kmod-erofs
Version:	%{kmod_driver_version}
Release:	1%{?dist}
Summary:	Kernel Modules for EROFS filesystem driver
License:	GPLv2
URL:		https://erofs.docs.kernel.org
Source0:	kmod-%{kmod_name}-%{kmod_driver_version}.tar.gz

BuildRequires:	kernel-abi-whitelists >= %{kmod_kernel_version}
BuildRequires:	kernel-devel >= %{kmod_kernel_version}
BuildRequires:	kernel-devel-uname-r >= %{kmod_kernel_version}.%{_arch}
BuildRequires:	gcc
BuildRequires:	kmod
BuildRequires:	make
BuildRequires:	redhat-rpm-config

Provides:	kmod-%{kmod_name} = %{?epoch:%{epoch}:}%{version}-%{release}
Obsoletes:	kmod-%{kmod_name} < %{?epoch:%{epoch}:}%{version}-%{release}

Requires(post):		%{_sbindir}/depmod
Requires(postun):	%{_sbindir}/depmod
Requires(post):		%{_sbindir}/weak-modules
Requires(postun):	%{_sbindir}/weak-modules

Requires:		kernel >= %{kmod_kernel_version}
Requires:		kernel-uname-r >= %{kmod_kernel_version}.%{_arch}

# If there are multiple kmods for the same driver from different vendors,
# they should conflict with each other.
Conflicts:	kmod-%{kmod_name}

%description
This package provides the kernel modules for EROFS filesystem driver.

%prep
%setup -n kmod-%{kmod_name}-%{kmod_driver_version}

%build
pushd src
%{__make} -C /usr/src/kernels/%{kmod_headers_version} M=$PWD %{?_smp_mflags} CONFIG_EROFS_FS=m %{?erofs_kcfgs} modules
#%{__make} -C %{kernel_source} M=$PWD CONFIG_EROFS_FS=m modules
popd

%install
mkdir -p %{buildroot}/lib/modules/%{kmod_headers_version}/extra/fs/%{kmod_name}
%{__install} -D -t %{buildroot}/lib/modules/%{kmod_headers_version}/extra/fs/%{kmod_name} src/%{kmod_name}.ko

# Make .ko objects temporarily executable for automatic stripping
find %{buildroot}/lib/modules -type f -name \*.ko -exec chmod u+x \{\} \+

%{__install} -d %{buildroot}/%{_sysconfdir}/depmod.d
for kmod in $(find %{buildroot}/lib/modules/%{kmod_headers_version}/extra -type f -name \*.ko -printf "%%P\n" | sort)
do
    echo "override $(basename $kmod .ko) * weak-updates/$(dirname $kmod)" >> %{buildroot}/%{_sysconfdir}/depmod.d/%{kmod_name}.conf
    echo "override $(basename $kmod .ko) * extra/$(dirname $kmod)" >> %{buildroot}/%{_sysconfdir}/depmod.d/%{kmod_name}.conf
done

%clean
%{__rm} -rf %{buildroot}

%post
depmod -a > /dev/null 2>&1
if [ -x "/usr/sbin/weak-modules" ]; then
    printf '%s\n' "/lib/modules/%{kmod_headers_version}/extra/fs/%{kmod_name}/%{kmod_name}.ko" | /usr/sbin/weak-modules --no-initramfs --add-modules
fi

%preun
echo "/lib/modules/%{kmod_headers_version}/extra/fs/%{kmod_name}/%{kmod_name}.ko" >> /var/run/rpm-%{kmod_name}-modules.list

%postun
depmod -a > /dev/null 2>&1

if [ -x "/usr/sbin/weak-modules" ]; then
    modules=( $(cat /var/run/rpm-%{kmod_name}-modules.list) )
    printf '%s\n' "${modules[@]}" | /usr/sbin/weak-modules --no-initramfs --remove-modules
fi
rm /var/run/rpm-%{kmod_name}-modules.list

%files
%defattr(644,root,root,755)
/lib/modules/%{kmod_headers_version}
%license LICENSES
%config(noreplace) %{_sysconfdir}/depmod.d/%{kmod_name}.conf

%changelog
* Wed May 29 2024 Gao Xiang <xiang@kernel.org> - 1
- Initial version
- kABI tracking kmod package (kernel >= 3.10.0-123.el7)
