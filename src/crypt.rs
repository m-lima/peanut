const TAG_LEN: usize = 16;

pub struct Cryptor<Out, const BLOCK: usize>
where
    Out: std::io::Write,
{
    stream: Option<aead::stream::EncryptorBE32<aes_gcm_siv::Aes256GcmSiv>>,
    buffer: aead::arrayvec::ArrayVec<u8, BLOCK>,
    output: Out,
}

impl<Out, const BLOCK: usize> Cryptor<Out, BLOCK>
where
    Out: std::io::Write,
{
    const MAX_CAP: usize = BLOCK - TAG_LEN;

    pub fn new(key: [u8; 32], mut output: Out) -> anyhow::Result<Self> {
        use aead::KeyInit;
        use anyhow::Context;

        let nonce = make_nonce();

        output.write_all(&nonce).context("Could not write nonce")?;

        let stream = Some(aead::stream::EncryptorBE32::from_aead(
            aes_gcm_siv::Aes256GcmSiv::new(key.as_slice().into()),
            nonce.as_slice().into(),
        ));
        let buffer = aead::arrayvec::ArrayVec::new();

        Ok(Self {
            stream,
            buffer,
            output,
        })
    }

    fn fill_buffer(&mut self, buf: &[u8]) -> std::io::Result<()> {
        use aead::Buffer;

        self.buffer
            .extend_from_slice(buf)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::OutOfMemory, err.to_string()))
    }

    fn flush_block(&mut self) -> std::io::Result<()> {
        // SAFETY: The option is only removed on drop
        unsafe {
            self.stream
                .as_mut()
                .unwrap_unchecked()
                .encrypt_next_in_place(b"", &mut self.buffer)
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err.to_string()))?;
        }

        self.output.write_all(&self.buffer)?;
        self.buffer.clear();
        Ok(())
    }
}

impl<Out, const BLOCK: usize> std::io::Write for Cryptor<Out, BLOCK>
where
    Out: std::io::Write,
{
    fn write(&mut self, mut buf: &[u8]) -> std::io::Result<usize> {
        let mut sent = 0;
        let mut capacity = Self::MAX_CAP.saturating_sub(self.buffer.len());

        while buf.len() > capacity {
            self.fill_buffer(&buf[..capacity])?;
            self.flush_block()?;

            buf = &buf[capacity..];
            sent += capacity;
            capacity = Self::MAX_CAP;
        }

        self.fill_buffer(buf)?;

        Ok(sent + self.buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if self.buffer.len() == Self::MAX_CAP {
            self.flush_block()?;
        }
        self.output.flush()
    }
}

impl<Out, const BLOCK: usize> Drop for Cryptor<Out, BLOCK>
where
    Out: std::io::Write,
{
    fn drop(&mut self) {
        fn finish<Out, const BLOCK: usize>(this: &mut Cryptor<Out, BLOCK>) -> anyhow::Result<()>
        where
            Out: std::io::Write,
        {
            use anyhow::Context;

            // SAFETY: The option is only removed on drop
            unsafe {
                this.stream
                    .take()
                    .unwrap_unchecked()
                    .encrypt_last_in_place(b"", &mut this.buffer)
                    .map_err(|err| anyhow::anyhow!("Could not encrypt the last block: {err}"))?;
            }

            this.output
                .write_all(&this.buffer)
                .context("Could not write the last block")?;
            this.output
                .flush()
                .context("Could not flush the last block")
        }

        if let Err(err) = finish(self) {
            error!("Failed to drop Cryptor: {err:?}");
        }
    }
}

pub struct Decryptor<In, const BLOCK: usize>
where
    In: std::io::Read,
{
    stream: Option<aead::stream::DecryptorBE32<aes_gcm_siv::Aes256GcmSiv>>,
    buffer: aead::arrayvec::ArrayVec<u8, BLOCK>,
    cursor: usize,
    input: In,
}

impl<In, const BLOCK: usize> Decryptor<In, BLOCK>
where
    In: std::io::Read,
{
    pub fn new(key: [u8; 32], mut input: In) -> anyhow::Result<Self> {
        use aead::KeyInit;
        use anyhow::Context;

        let mut nonce = super::make_buffer::<7>();
        input
            .read_exact(&mut nonce)
            .context("Could not read nonce")?;

        let stream = Some(aead::stream::DecryptorBE32::from_aead(
            aes_gcm_siv::Aes256GcmSiv::new(key.as_slice().into()),
            nonce.as_slice().into(),
        ));
        let buffer = aead::arrayvec::ArrayVec::new();

        Ok(Self {
            stream,
            buffer,
            cursor: 0,
            input,
        })
    }

    fn fill_buf(&mut self) -> std::io::Result<()> {
        unsafe { self.buffer.set_len(BLOCK) };
        let mut read = 0;
        while read < BLOCK {
            read += {
                let bytes = self.input.read(&mut self.buffer[read..])?;
                if bytes == 0 {
                    break;
                }
                bytes
            };
        }
        unsafe { self.buffer.set_len(read) };
        self.cursor = 0;
        Ok(())
    }

    unsafe fn decrypt(&mut self) -> std::io::Result<()> {
        if self.buffer.len() < BLOCK {
            self.stream
                .take()
                .unwrap_unchecked()
                .decrypt_last_in_place(b"", &mut self.buffer)
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err.to_string()))?;
        } else {
            self.stream
                .as_mut()
                .unwrap_unchecked()
                .decrypt_next_in_place(b"", &mut self.buffer)
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err.to_string()))?;
        }

        Ok(())
    }
}

impl<In, const BLOCK: usize> std::io::Read for Decryptor<In, BLOCK>
where
    In: std::io::Read,
{
    fn read(&mut self, mut buf: &mut [u8]) -> std::io::Result<usize> {
        let mut read = 0;
        while !buf.is_empty() {
            let buf_size = self.buffer.len() - self.cursor;
            if buf_size > 0 {
                let len = buf_size.min(buf.len());
                buf[..len].copy_from_slice(&self.buffer[self.cursor..self.cursor + len]);
                self.cursor += len;
                buf = &mut buf[len..];
                read += len;

                continue;
            }

            if self.stream.is_none() {
                break;
            }
            self.fill_buf()?;
            // SAFETY: The presence of `self.stream` was checked above
            unsafe {
                self.decrypt()?;
            }
        }
        Ok(read)
    }
}

fn make_nonce() -> [u8; 7] {
    let mut nonce = super::make_buffer();
    aead::rand_core::RngCore::fill_bytes(&mut aead::OsRng, &mut nonce);
    nonce
}
