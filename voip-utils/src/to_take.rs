pub struct ToTake<'a, T: 'a> {
    inner: &'a mut Option<T>
}


impl<'a, T: 'a> ToTake<'a, T> {
    pub const fn new(inner: &'a mut Option<T>) -> Self {
        assert!(inner.is_some());

        Self { inner }
    }
    
    pub fn take(&'a mut self) -> T {
        self.inner.take().unwrap()
    }
}

impl <'a, T> std::ops::Deref for ToTake<'a, T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.inner.as_ref().unwrap()
    }
}

impl <'a, T> std::ops::DerefMut for ToTake<'a, T> {
    fn deref_mut(&mut self) -> &mut T {
        self.inner.as_mut().unwrap()
    }
}