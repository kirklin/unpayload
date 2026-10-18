use crate::error::Result;

/// Destination for bytes produced in order.
pub(crate) trait Sink {
    fn put(&mut self, data: &[u8]) -> Result<()>;
}

impl Sink for Vec<u8> {
    fn put(&mut self, data: &[u8]) -> Result<()> {
        self.extend_from_slice(data);
        Ok(())
    }
}

impl Sink for crate::extent::ExtentWriter<'_> {
    fn put(&mut self, data: &[u8]) -> Result<()> {
        self.write(data)
    }
}
