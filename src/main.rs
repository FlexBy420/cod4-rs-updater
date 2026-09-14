use base64::{engine::general_purpose::STANDARD, Engine};
use rsa::{
    pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey},
    Pss, RsaPrivateKey, RsaPublicKey,
};
use serde_json::{json, Value};
use std::{
    env,
    fs::{self, File},
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tiger::{Digest, Tiger};

const HOST: &str = "cod4mw-ps3update.charlieoscardelta.com";
const PUBLIC_KEY: &[u8] = include_bytes!("original_public_key.der");
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

struct Config {
    file: PathBuf,
    signature: Option<PathBuf>,
    private_key: Option<PathBuf>,
    signature_out: Option<PathBuf>,
    sign_only: bool,
    public_key: Option<PathBuf>,
    bind: String,
    base_url: String,
    title: String,
    current: String,
    version: String,
    destination: String,
    message: String,
    diagnostic: bool,
    no_update: bool,
    required_kb: Option<u64>,
}
impl Config {
    fn parse() -> Result<Self> {
        let mut c = Self {
            file: PathBuf::new(),
            signature: None,
            private_key: None,
            signature_out: None,
            sign_only: false,
            public_key: None,
            bind: "0.0.0.0:80".into(),
            base_url: format!("http://{HOST}"),
            title: "BLUS30072".into(),
            current: "1.3".into(),
            version: "1.4".into(),
            destination: "test.bin".into(),
            message: "An update is available. Do you wish to update now?".into(),
            diagnostic: false,
            no_update: false,
            required_kb: None,
        };
        let mut args = env::args().skip(1);
        while let Some(a) = args.next() {
            if a == "--help" || a == "-h" {
                println!("COD4 patcher HTTP server\n\n--file PATH (required)\n--signature PATH  Base64 RSA-PSS/Tiger signature with ORIGINAL key, zero salt\n--private-key PATH  PKCS#1 PEM; auto-sign for the matching RPCS3 key patch\n--public-key PATH  Optional PKCS#1 DER validation key\n--signature-out PATH  Save generated/validated Base64 signature\n--sign-only  Sign/verify and exit without TCP (requires signature-out)\n--diagnostic-unsigned  Intentionally invalid signature; client will reject\n--no-update  Return 404 for manifest; still serve selected file\n--bind ADDR  [0.0.0.0:80]\n--base-url URL  [http://{HOST}]\n--title ID [BLUS30072]\n--current VERSION [1.3]  Existing client GAME.VER; absent file means 1.0\n--version VERSION [1.4]\n--destination RELATIVE_PATH [test.bin]\n--message TEXT\n--required-kb INTEGER  Override estimated temporary + destination disk space\n\nWithout a signature, only transport/no-update mode is available.");
                std::process::exit(0);
            }
            match a.as_str() {
                "--diagnostic-unsigned" => c.diagnostic = true,
                "--no-update" => c.no_update = true,
                "--sign-only" => c.sign_only = true,
                _ => {
                    let v = args
                        .next()
                        .ok_or_else(|| format!("Missing value for {a}"))?;
                    match a.as_str() {
                        "--file" => c.file = v.into(),
                        "--signature" => c.signature = Some(v.into()),
                        "--private-key" => c.private_key = Some(v.into()),
                        "--signature-out" => c.signature_out = Some(v.into()),
                        "--public-key" => c.public_key = Some(v.into()),
                        "--bind" => c.bind = v,
                        "--base-url" => c.base_url = v.trim_end_matches('/').into(),
                        "--title" => c.title = v,
                        "--current" => c.current = v,
                        "--version" => c.version = v,
                        "--destination" => c.destination = v,
                        "--message" => c.message = v,
                        "--required-kb" => c.required_kb = Some(v.parse()?),
                        _ => return Err(format!("Unknown option: {a}").into()),
                    }
                }
            }
        }
        if c.file.as_os_str().is_empty() {
            return Err("--file is required; use --help".into());
        }
        for (name, value) in [
            ("title", &c.title),
            ("current", &c.current),
            ("version", &c.version),
            ("destination", &c.destination),
            ("base-url", &c.base_url),
        ] {
            if value.is_empty()
                || !value.is_ascii()
                || value.bytes().any(|b| b.is_ascii_whitespace() || b == 0)
            {
                return Err(format!("Invalid {name}: must be a nonempty ASCII token").into());
            }
        }
        for value in [&c.title, &c.current, &c.version] {
            if !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
                || value == "."
                || value == ".."
            {
                return Err("Invalid title/version path token".into());
            }
        }
        if c.destination.starts_with('/')
            || c.destination.contains('\\')
            || c.destination
                .split('/')
                .any(|s| s == ".." || s == "." || s.is_empty())
            || c.destination.len() > 400
        {
            return Err("destination must be a safe relative path, <=400 bytes".into());
        }
        if c.destination == "GAME.VER" {
            return Err("GAME.VER is reserved for the client's version marker".into());
        }
        if !c.base_url.starts_with("http://") || c.base_url.len() > 800 {
            return Err("base-url must be http:// and <=800 bytes".into());
        }
        if c.message.len() > 500
            || c.message.contains(['\r', '\n', '\0', '['])
            || c.message.contains("\\n")
        {
            return Err(
                "message must be one line, <=500 bytes, without [, NUL or escaped newline".into(),
            );
        }
        if usize::from(c.signature.is_some())
            + usize::from(c.private_key.is_some())
            + usize::from(c.diagnostic)
            > 1
        {
            return Err(
                "signature, private-key and diagnostic-unsigned are mutually exclusive".into(),
            );
        }
        if c.version == c.current && !c.no_update {
            return Err("new version must differ from current".into());
        }
        Ok(c)
    }
}

fn verify(payload: &[u8], signature: &[u8]) -> Result<()> {
    let key = RsaPublicKey::from_pkcs1_der(PUBLIC_KEY)?;
    key.verify(
        Pss::new_with_salt::<Tiger>(0),
        &Tiger::digest(payload),
        signature,
    )?;
    Ok(())
}

fn manifest(c: &Config, size: usize, signature: &str) -> Result<Vec<u8>> {
    let kb = c
        .required_kb
        .unwrap_or((size as u64).div_ceil(1024) * 2 + 4096);
    if kb > i32::MAX as u64 {
        return Err("required-kb exceeds the client's signed integer range".into());
    }
    // The client allocates length+1 but does not append NUL. Include it in the body.
    Ok(format!(
        "{}\n{}\n{}\n{}/payload.bin {} {}\n\0",
        c.message, c.version, kb, c.base_url, c.destination, signature
    )
    .into_bytes())
}

struct Logger(Mutex<File>);
impl Logger {
    fn event(&self, value: Value) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let line = json!({"timestamp_unix_ms": now.as_millis(), "event": value}).to_string();
        println!("{line}");
        if let Ok(mut f) = self.0.lock() {
            if let Err(e) = writeln!(f, "{line}").and_then(|_| f.flush()) {
                eprintln!("log write failed: {e}");
            }
        }
    }
}
struct State {
    c: Config,
    payload: Vec<u8>,
    manifest: Option<Vec<u8>>,
    logger: Logger,
}

fn respond(
    stream: &mut TcpStream,
    s: &State,
    peer: &str,
    endpoint: &str,
    code: u16,
    body: &[u8],
    kind: &str,
    head: bool,
) -> io::Result<()> {
    let reason = match code {
        200 => "OK",
        404 => "Not Found",
        405 => "Method Not Allowed",
        400 => "Bad Request",
        413 => "Content Too Large",
        _ => "Error",
    };
    let headers = format!("HTTP/1.1 {code} {reason}\r\nContent-Length: {}\r\nContent-Type: {kind}\r\nConnection: close\r\n\r\n", body.len());
    s.logger.event(json!({"type":"response", "source":peer,"endpoint":endpoint,"status":code,"headers":headers,"response_size":body.len(),"body":if endpoint.ends_with("GAME.VER") {Some(String::from_utf8_lossy(body).to_string())} else {None},"head":head}));
    stream.write_all(headers.as_bytes())?;
    if !head {
        let mut offset = 0;
        for chunk in body.chunks(256 * 1024) {
            stream.write_all(chunk)?;
            s.logger.event(json!({"type":"transfer", "source":peer,"endpoint":endpoint,"status":code,"file":if code==200 && endpoint=="/payload.bin" {Some(s.c.file.display().to_string())} else {None},"offset":offset,"block_bytes":chunk.len(),"bytes_sent":offset+chunk.len(),"total":body.len()}));
            offset += chunk.len();
        }
    }
    stream.flush()
}

fn handle(mut stream: TcpStream, s: &State) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(15)))?;
    stream.set_write_timeout(Some(Duration::from_secs(15)))?;
    let peer = stream.peer_addr()?.to_string();
    let mut raw = Vec::new();
    let end;
    loop {
        if let Some(i) = raw.windows(4).position(|v| v == b"\r\n\r\n") {
            end = i + 4;
            break;
        }
        if raw.len() >= 32768 {
            respond(
                &mut stream,
                s,
                &peer,
                "",
                413,
                b"Header too large\n",
                "text/plain",
                false,
            )?;
            return Ok(());
        }
        let mut buf = [0; 2048];
        let n = stream.read(&mut buf)?;
        if n == 0 {
            return Err("Incomplete request headers".into());
        }
        raw.extend_from_slice(&buf[..n]);
    }
    let header_text = std::str::from_utf8(&raw[..end])?.to_string();
    let mut lines = header_text.split("\r\n");
    let request = lines.next().unwrap_or_default();
    let parts: Vec<_> = request.split_whitespace().collect();
    if parts.len() != 3 || !["HTTP/1.0", "HTTP/1.1"].contains(&parts[2]) {
        respond(
            &mut stream,
            s,
            &peer,
            "",
            400,
            b"Bad request\n",
            "text/plain",
            false,
        )?;
        return Ok(());
    }
    let method = parts[0];
    let endpoint = parts[1];
    let mut length = 0usize;
    let mut length_seen = false;
    for line in lines.filter(|l| !l.is_empty()) {
        let (name, value) = line.split_once(':').ok_or("Malformed header")?;
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err("Transfer-Encoding requests are not supported".into());
        }
        if name.eq_ignore_ascii_case("content-length") {
            if length_seen {
                return Err("Duplicate Content-Length".into());
            }
            length_seen = true;
            length = value.trim().parse()?;
        }
        if name.eq_ignore_ascii_case("expect") {
            return Err("Expect requests are not supported".into());
        }
    }
    if length > 65536 {
        respond(
            &mut stream,
            s,
            &peer,
            endpoint,
            413,
            b"Body too large\n",
            "text/plain",
            false,
        )?;
        return Ok(());
    }
    while raw.len() < end + length {
        let mut buf = [0; 4096];
        let n = stream.read(&mut buf)?;
        if n == 0 {
            return Err("Incomplete body".into());
        }
        raw.extend_from_slice(&buf[..n]);
    }
    let body = &raw[end..end + length];
    s.logger.event(json!({"type":"request","source":peer,"destination":stream.local_addr()?.to_string(),"endpoint":endpoint,"method":method,"headers":header_text,"body_ascii":String::from_utf8_lossy(body),"body_hex":body.iter().map(|b|format!("{b:02x}")).collect::<String>(),"body_size":length}));
    if method != "GET" && method != "HEAD" {
        respond(
            &mut stream,
            s,
            &peer,
            endpoint,
            405,
            b"GET required\n",
            "text/plain",
            false,
        )?;
        return Ok(());
    }
    let path = endpoint.split('?').next().unwrap_or(endpoint);
    let manifest_path = format!("/{}/{}/GAME.VER", s.c.title, s.c.current);
    let (code, body, kind) = if path == "/payload.bin" {
        (200, s.payload.as_slice(), "application/octet-stream")
    } else if path == manifest_path {
        match s.manifest.as_deref() {
            Some(m) => (200, m, "text/plain"),
            None => (404, b"No update\n".as_slice(), "text/plain"),
        }
    } else {
        (404, b"Not found\n".as_slice(), "text/plain")
    };
    respond(
        &mut stream,
        s,
        &peer,
        path,
        code,
        body,
        kind,
        method == "HEAD",
    )?;
    Ok(())
}

fn main() -> Result<()> {
    let c = Config::parse()?;
    let payload = fs::read(&c.file)?;
    if payload.is_empty() || payload.len() > i32::MAX as usize {
        return Err(
            "payload must be nonempty and <=2 GiB-1; PS3 RAM imposes a much lower practical limit"
                .into(),
        );
    }
    let signature = if let Some(path) = &c.private_key {
        let key = RsaPrivateKey::from_pkcs1_pem(&fs::read_to_string(path)?)?;
        let public = RsaPublicKey::from(&key);
        let sig = key.sign_with_rng(
            &mut rsa::rand_core::OsRng,
            Pss::new_with_salt::<Tiger>(0),
            &Tiger::digest(&payload),
        )?;
        public.verify(
            Pss::new_with_salt::<Tiger>(0),
            &Tiger::digest(&payload),
            &sig,
        )?;
        if let Some(public_path) = &c.public_key {
            let expected = RsaPublicKey::from_pkcs1_der(&fs::read(public_path)?)?;
            if expected != public {
                return Err("private-key and public-key do not match".into());
            }
        }
        Some(STANDARD.encode(sig))
    } else if let Some(path) = &c.signature {
        let b64 = fs::read_to_string(path)?
            .split_whitespace()
            .collect::<String>();
        let sig = STANDARD.decode(&b64)?;
        if let Some(public_path) = &c.public_key {
            let key = RsaPublicKey::from_pkcs1_der(&fs::read(public_path)?)?;
            key.verify(
                Pss::new_with_salt::<Tiger>(0),
                &Tiger::digest(&payload),
                &sig,
            )?;
        } else {
            verify(&payload, &sig)?;
        }
        Some(STANDARD.encode(sig))
    } else if c.diagnostic {
        Some(STANDARD.encode([0u8; 128]))
    } else {
        None
    };
    if let Some(path) = &c.signature_out {
        let sig = signature
            .as_ref()
            .ok_or("signature-out requires signature or private-key")?;
        fs::write(path, format!("{sig}\n"))?;
    }
    if c.sign_only {
        if c.signature_out.is_none() {
            return Err("sign-only requires signature-out".into());
        }
        return Ok(());
    }
    let manifest = if c.no_update {
        None
    } else {
        signature
            .as_deref()
            .map(|v| manifest(&c, payload.len(), v))
            .transpose()?
    };
    let log_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("logs");
    fs::create_dir_all(&log_dir)?;
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    let log_path = log_dir.join(format!("session-{stamp}-{}.jsonl", std::process::id()));
    let logger = Logger(Mutex::new(File::create(&log_path)?));
    let listener = TcpListener::bind(&c.bind)?;
    logger.event(json!({"type":"startup","bind":listener.local_addr()?.to_string(),"file":c.file.display().to_string(),"size":payload.len(),"tiger_hex":Tiger::digest(&payload).iter().map(|b|format!("{b:02x}")).collect::<String>(),"signature_validated":c.signature.is_some() || c.private_key.is_some(),"private_key_signing":c.private_key.is_some(),"public_key":c.public_key.as_ref().map(|p|p.display().to_string()),"diagnostic_unsigned":c.diagnostic,"manifest_enabled":manifest.is_some(),"manifest_path":format!("/{}/{}/GAME.VER",c.title,c.current),"destination":c.destination,"logs":log_path.display().to_string()}));
    if signature.is_none() {
        eprintln!("No signature: serving payload only; manifest returns 404. Use --signature for accepted payload or --diagnostic-unsigned to test rejection.");
    }
    let state = Arc::new(State {
        c,
        payload,
        manifest,
        logger,
    });
    for connection in listener.incoming() {
        match connection {
            Ok(stream) => {
                let s = Arc::clone(&state);
                let peer = stream
                    .peer_addr()
                    .map(|p| p.to_string())
                    .unwrap_or_default();
                thread::spawn(move || {
                    if let Err(e) = handle(stream, &s) {
                        s.logger
                            .event(json!({"type":"error","source":peer,"error":e.to_string()}));
                    }
                });
            }
            Err(e) => state
                .logger
                .event(json!({"type":"accept_error","error":e.to_string()})),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::RsaPrivateKey;
    #[test]
    fn tiger_known_vector() {
        assert_eq!(
            Tiger::digest(b"abc")
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            "2aab1484e8c158f2bfb8c5ff41b57a525129131c957b5f93"
        );
    }
    #[test]
    fn original_key_rejects_fake_signature() {
        assert!(verify(b"test", &[0; 128]).is_err());
    }
    #[test]
    fn pss_zero_salt_roundtrip_and_tamper() {
        let private = RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 1024).unwrap();
        let public = RsaPublicKey::from(&private);
        let digest = Tiger::digest(b"fixture");
        let sig = private
            .sign_with_rng(
                &mut rsa::rand_core::OsRng,
                Pss::new_with_salt::<Tiger>(0),
                &digest,
            )
            .unwrap();
        public
            .verify(Pss::new_with_salt::<Tiger>(0), &digest, &sig)
            .unwrap();
        assert!(public
            .verify(
                Pss::new_with_salt::<Tiger>(0),
                &Tiger::digest(b"changed"),
                &sig
            )
            .is_err());
        assert!(verify(b"fixture", &sig).is_err());
    }
}
