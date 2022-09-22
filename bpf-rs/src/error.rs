type RawInt = std::os::raw::c_int;

// If this changes, it's a breaking changing
pub type Errno = nix::errno::Errno;

fn errno() -> Errno {
    return nix::errno::Errno::last();
}

// libbpf returns the actual error code as negative so when this happens
// we return Err with the (positive) error code
pub(crate) fn from_libbpf_int(result: RawInt) -> Result<RawInt, RawInt> {
    if result < 0 {
        return Err(-result);
    }

    Ok(result)
}

// If we know that the negative error code returned from libbpf will be
// a standard errno, let's return that. Note that we are forcing dependants to
// also use nix
pub(crate) fn from_libbpf_errno(result: RawInt) -> Result<RawInt, Errno> {
    if result < 0 {
        return Err(nix::errno::from_i32(-result));
    }

    Ok(result)
}

// In libbpf v1, ptr-returning functions will return NULL on error but set
// the errno to a valid (positive) error code
pub(crate) fn from_libbpf_ptr<P>(ptr: *const P) -> Result<*const P, Errno> {
    if ptr.is_null() {
        return Err(errno());
    }

    Ok(ptr)
}
