macro_rules! error {
    () => {
        eprintln!()
    };
    ($($arg: tt)*) => {{
        eprint!("[31mError:[m ");
        eprintln!($($arg)*);
    }};
}

mod args;

const BUF_LEN: usize = 8 * 1024;
const TAG_LEN: usize = 16;

fn main() -> std::process::ExitCode {
    if let Err(err) = fallible_main() {
        error!("{err:?}");
        return std::process::ExitCode::FAILURE;
    }

    std::process::ExitCode::SUCCESS
}

fn fallible_main() -> anyhow::Result<()> {
    let command = args::parse()?;

    let stdin = std::io::stdin().lock();
    let stdout = std::io::stdout().lock();

    match command {
        args::Command::Encrypt(key) => encrypt(key, stdin, stdout),
        args::Command::Decrypt(_) => decrypt(stdin, stdout),
    }
}

fn encrypt<Input, Output>(key: [u8; 32], input: Input, output: Output) -> anyhow::Result<()>
where
    Input: std::io::Read,
    Output: std::io::Write,
{
    let encryptor = Cryptor::new(key, output)?;
    stream(input, zstd::Encoder::new(encryptor, 9)?.auto_finish())
}

struct Cryptor<Out>
where
    Out: std::io::Write,
{
    stream: Option<aead::stream::EncryptorLE31<aes_gcm_siv::Aes256GcmSiv>>,
    buffer: aead::arrayvec::ArrayVec<u8, BUF_LEN>,
    out: Out,
}

impl<Out> Cryptor<Out>
where
    Out: std::io::Write,
{
    fn new(key: [u8; 32], mut out: Out) -> anyhow::Result<Self> {
        use aead::KeyInit;
        use anyhow::Context;

        let nonce = make_nonce();
        let key = derive_key(key, nonce);

        out.write_all(&nonce).context("Could not write nonce")?;

        let stream = Some(aead::stream::EncryptorLE31::from_aead(
            aes_gcm_siv::Aes256GcmSiv::new(key.as_slice().into()),
            [0; 8].as_slice().into(),
        ));
        let buffer = aead::arrayvec::ArrayVec::new();

        Ok(Self {
            stream,
            buffer,
            out,
        })
    }

    fn finish(&mut self) -> anyhow::Result<()> {
        use anyhow::Context;

        if !self.buffer.is_empty() {
            self.stream
                .take()
                .unwrap()
                .encrypt_last_in_place(b"", &mut self.buffer)
                .map_err(|err| anyhow::anyhow!("Could not encrypt the last block: {err}"))?;

            self.out
                .write_all(&self.buffer)
                .context("Could not write the last block")?;
        }
        self.out.flush().context("Could not flush the last block")
    }
}

impl<Out> std::io::Write for Cryptor<Out>
where
    Out: std::io::Write,
{
    fn write(&mut self, mut buf: &[u8]) -> std::io::Result<usize> {
        use aead::Buffer;

        const MAX_CAP: usize = BUF_LEN - TAG_LEN;

        let mut sent = 0;
        let mut capacity = MAX_CAP - self.buffer.len();

        // let id = *buf.first().unwrap_or(&0);

        // eprintln!(
        //     "{id} Write :: Len: {len}, Cap: {capacity}, Buf: {buf}",
        //     len = self.buffer.len(),
        //     buf = buf.len()
        // );

        while buf.len() > capacity {
            // eprintln!("{id} Need to flush");
            self.buffer
                .extend_from_slice(&buf[..capacity])
                .map_err(|err| {
                    std::io::Error::new(std::io::ErrorKind::OutOfMemory, err.to_string())
                })?;

            // eprintln!(
            //     "{id} Extend :: Len: {len}, Cap: {capacity}, Buf: {buf}, Snt: {sent}",
            //     len = self.buffer.len(),
            //     buf = buf.len()
            // );

            self.stream
                .as_mut()
                .unwrap()
                .encrypt_next_in_place(b"", &mut self.buffer)
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err.to_string()))?;

            self.out.write_all(&self.buffer)?;

            self.buffer.clear();
            buf = &buf[capacity..];
            sent += capacity;
            capacity = MAX_CAP;

            // eprintln!(
            //     "{id} Rotate :: Len: {len}, Cap: {capacity}, Buf: {buf}, Snt: {sent}",
            //     len = self.buffer.len(),
            //     buf = buf.len()
            // );
        }

        self.buffer
            .extend_from_slice(buf)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::OutOfMemory, err.to_string()))?;

        Ok(sent + self.buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if !self.buffer.is_empty() {
            self.stream
                .as_mut()
                .unwrap()
                .encrypt_next_in_place(b"", &mut self.buffer)
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err.to_string()))?;

            self.out.write_all(&self.buffer)?;
        }
        self.out.flush()
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

fn decrypt<Input, Output>(input: Input, output: Output) -> anyhow::Result<()>
where
    Input: std::io::Read,
    Output: std::io::Write,
{
    stream(zstd::Decoder::new(input)?, output)
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

fn stream<Input, Output>(mut input: Input, mut output: Output) -> anyhow::Result<()>
where
    Input: std::io::Read,
    Output: std::io::Write,
{
    use anyhow::Context;

    let mut buf = unsafe {
        std::mem::transmute::<_, [u8; BUF_LEN]>([std::mem::MaybeUninit::<u8>::uninit(); BUF_LEN])
    };

    loop {
        let bytes = input
            .read(&mut buf)
            .context("Error while reading from stdin")?;

        if bytes == 0 {
            return Ok(());
        }

        if let Err(err) = output.write_all(&buf[..bytes]) {
            error!("Error while writing to stdout: {}: {err}", err.kind());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transparent_round_trip() {
        let input = (u8::MIN..=u8::MAX)
            .flat_map(|_| (u8::MIN..u8::MAX))
            .collect::<Vec<_>>();

        let mut output = Vec::with_capacity(usize::from(u8::MAX) * usize::from(u8::MAX));

        stream(input.as_slice(), &mut output).unwrap();

        assert_eq!(input, output);
    }

    #[test]
    fn round_trip() {
        let input = (u8::MIN..=u8::MAX)
            .flat_map(|_| (u8::MIN..u8::MAX))
            .collect::<Vec<_>>();

        let mut transient = Vec::with_capacity(usize::from(u8::MAX) * usize::from(u8::MAX));
        let mut output = Vec::with_capacity(usize::from(u8::MAX) * usize::from(u8::MAX));

        encrypt([0; 32], input.as_slice(), &mut transient).unwrap();
        decrypt(transient.as_slice(), &mut output).unwrap();

        assert_eq!(input, output);
    }
}
