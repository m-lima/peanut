use super::BUF_LEN;
const TAG_LEN: usize = 16;

pub struct Cryptor<Out>
where
    Out: std::io::Write,
{
    // TODO: This option here is kinda ridiculous
    stream: Option<aead::stream::EncryptorBE32<aes_gcm_siv::Aes256GcmSiv>>,
    buffer: aead::arrayvec::ArrayVec<u8, BUF_LEN>,
    output: Out,
}

impl<Out> Cryptor<Out>
where
    Out: std::io::Write,
{
    pub fn new(key: [u8; 32], mut output: Out) -> anyhow::Result<Self> {
        use aead::KeyInit;
        use anyhow::Context;

        let nonce = make_nonce();
        let key = derive_key(key, nonce);

        output.write_all(&nonce).context("Could not write nonce")?;

        let stream = Some(aead::stream::EncryptorBE32::from_aead(
            aes_gcm_siv::Aes256GcmSiv::new(key.as_slice().into()),
            [0; 7].as_slice().into(),
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

    fn send_block(&mut self, buf: &[u8]) -> std::io::Result<()> {
        self.fill_buffer(buf)?;

        self.stream
            .as_mut()
            .unwrap()
            .encrypt_next_in_place(b"", &mut self.buffer)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err.to_string()))?;

        self.output.write_all(&self.buffer)?;
        self.buffer.clear();
        Ok(())
    }

    fn finish(&mut self) -> anyhow::Result<()> {
        use anyhow::Context;

        if !self.buffer.is_empty() {
            self.stream
                .take()
                .unwrap()
                .encrypt_last_in_place(b"", &mut self.buffer)
                .map_err(|err| anyhow::anyhow!("Could not encrypt the last block: {err}"))?;

            self.output
                .write_all(&self.buffer)
                .context("Could not write the last block")?;
        }
        self.output
            .flush()
            .context("Could not flush the last block")
    }
}

impl<Out> std::io::Write for Cryptor<Out>
where
    Out: std::io::Write,
{
    fn write(&mut self, mut buf: &[u8]) -> std::io::Result<usize> {
        const MAX_CAP: usize = BUF_LEN - TAG_LEN;

        let mut sent = 0;
        let mut capacity = MAX_CAP - self.buffer.len();

        while buf.len() > capacity {
            self.send_block(&buf[..capacity])?;
            buf = &buf[capacity..];
            sent += capacity;
            capacity = MAX_CAP;
        }

        self.fill_buffer(buf)?;

        Ok(sent + self.buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if !self.buffer.is_empty() {
            self.stream
                .as_mut()
                .unwrap()
                .encrypt_next_in_place(b"", &mut self.buffer)
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err.to_string()))?;

            self.output.write_all(&self.buffer)?;
        }
        self.output.flush()
    }
}

impl<Out> Drop for Cryptor<Out>
where
    Out: std::io::Write,
{
    fn drop(&mut self) {
        if let Err(err) = self.finish() {
            error!("Failed to drop Cryptor: {err:?}");
        }
    }
}

pub struct Decryptor<In>
where
    In: std::io::Read,
{
    stream: Option<aead::stream::DecryptorBE32<aes_gcm_siv::Aes256GcmSiv>>,
    buffer: aead::arrayvec::ArrayVec<u8, BUF_LEN>,
    cursor: usize,
    input: In,
}

impl<In> Decryptor<In>
where
    In: std::io::Read,
{
    pub fn new(key: [u8; 32], mut input: In) -> anyhow::Result<Self> {
        use aead::KeyInit;
        use anyhow::Context;

        let mut nonce = [0; 24];
        input
            .read_exact(&mut nonce)
            .context("Could not read nonce")?;

        let key = derive_key(key, nonce);

        let stream = Some(aead::stream::DecryptorBE32::from_aead(
            aes_gcm_siv::Aes256GcmSiv::new(key.as_slice().into()),
            [0; 7].as_slice().into(),
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
        unsafe { self.buffer.set_len(BUF_LEN) };
        let mut read = 0;
        while read < BUF_LEN {
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

    fn decrypt(&mut self) -> std::io::Result<()> {
        if self.buffer.len() < BUF_LEN {
            self.stream
                .take()
                .unwrap()
                .decrypt_last_in_place(b"", &mut self.buffer)
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err.to_string()))?;
        } else {
            self.stream
                .as_mut()
                .unwrap()
                .decrypt_next_in_place(b"", &mut self.buffer)
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err.to_string()))?;
        }

        Ok(())
    }
}

impl<In> std::io::Read for Decryptor<In>
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
            self.decrypt()?;
        }
        Ok(read)
    }
}

fn make_nonce() -> [u8; 24] {
    let mut nonce =
        unsafe { std::mem::transmute::<_, [u8; 24]>([std::mem::MaybeUninit::<u8>::uninit(); 24]) };
    aead::rand_core::RngCore::fill_bytes(&mut aead::OsRng, &mut nonce);
    nonce
}

fn derive_key(key: [u8; 32], nonce: [u8; 24]) -> [u8; 32] {
    nonce_extension::nonce_extension_aes256(key, nonce)
}
