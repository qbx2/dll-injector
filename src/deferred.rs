pub(crate) struct Deferred(Vec<Box<dyn FnOnce()>>);

impl Deferred {
    pub(crate) fn new() -> Self {
        Self(vec![])
    }

    pub(crate) fn push<F: FnOnce() + 'static>(&mut self, f: F) {
        self.0.push(Box::new(f));
    }

    pub(crate) fn clear(&mut self) {
        self.0.clear();
    }
}

impl Drop for Deferred {
    fn drop(&mut self) {
        for deferred in std::mem::take(&mut self.0).into_iter().rev() {
            deferred();
        }
    }
}
