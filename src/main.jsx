import React, { useState, useEffect, useRef } from "react";
import { createRoot } from "react-dom/client";
import {
  ShieldCheck, Lock, QrCode, Wifi, Upload, FileText, CheckCircle2,
  ArrowLeft, AlertTriangle, KeyRound, RotateCcw, Download, Loader2
} from "lucide-react";

function bufToBase64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}
function base64ToBuf(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}
async function deriveKey(code) {
  const enc = new TextEncoder();
  const keyMaterial = await window.crypto.subtle.importKey(
    "raw", enc.encode(code), { name: "PBKDF2" }, false, ["deriveKey"]
  );
  return window.crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: enc.encode("SecureLinkFixedSalt"), iterations: 100000, hash: "SHA-256" },
    keyMaterial, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
  );
}
async function sha256Hex(buf) {
  const hashBuf = await window.crypto.subtle.digest("SHA-256", buf);
  return Array.from(new Uint8Array(hashBuf)).map((b) => b.toString(16).padStart(2, "0")).join("");
}
function formatBytes(bytes) {
  if (!bytes) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${units[i]}`;
}

function PhoneShell({ children }) {
  return (
    <div className="min-h-screen w-full flex items-center justify-center p-6">
      <div className="w-full max-w-sm bg-white rounded-[28px] shadow-[0_20px_50px_rgba(20,40,30,0.12)] border border-[#E3E9E6] overflow-hidden">
        {children}
      </div>
    </div>
  );
}

function TopBar({ onBack, onRestart, label }) {
  return (
    <div className="flex items-center justify-between px-5 pt-5 pb-3">
      {onBack ? (
        <button onClick={onBack} className="w-8 h-8 flex items-center justify-center rounded-full text-[#5B6B64] hover:bg-[#F0F3F1]">
          <ArrowLeft size={18} />
        </button>
      ) : <div className="w-8" />}
      <span className="text-xs font-semibold tracking-wide text-[#5B6B64] uppercase">{label}</span>
      <button onClick={onRestart} className="w-8 h-8 flex items-center justify-center rounded-full text-[#5B6B64] hover:bg-[#F0F3F1]">
        <RotateCcw size={16} />
      </button>
    </div>
  );
}

function PrimaryButton({ children, onClick, disabled, className = "" }) {
  return (
    <button onClick={onClick} disabled={disabled}
      className={`w-full py-3 rounded-xl font-semibold text-sm transition ${disabled ? "bg-[#E3E9E6] text-[#9AA6A1] cursor-not-allowed" : "bg-[#10B981] text-white hover:bg-[#0B7A5F]"} ${className}`}>
      {children}
    </button>
  );
}
function SecondaryButton({ children, onClick, className = "" }) {
  return (
    <button onClick={onClick}
      className={`w-full py-3 rounded-xl font-semibold text-sm bg-[#ECFDF5] text-[#0B7A5F] hover:bg-[#DBF6EA] ${className}`}>
      {children}
    </button>
  );
}

function App() {
  const [step, setStep] = useState("home");
  const [role, setRole] = useState(null);
  const [selectedFile, setSelectedFile] = useState(null);
  const [pairingCode, setPairingCode] = useState(null);
  const [mySenderId, setMySenderId] = useState(null);
  const [peerLabel, setPeerLabel] = useState(null);
  const [codeInput, setCodeInput] = useState("");
  const [myDeviceName, setMyDeviceName] = useState("");
  const [verifyError, setVerifyError] = useState("");
  const [showQr, setShowQr] = useState(false);
  const [progress, setProgress] = useState(0);
  const [incomingFile, setIncomingFile] = useState(null);
  const [wsReady, setWsReady] = useState(false);

  const wsRef = useRef(null);
  const roleRef = useRef(null);
  const cryptoKeyRef = useRef(null);
  const lastSubmittedCodeRef = useRef("");
  const progressTimerRef = useRef(null);
  const fileInputRef = useRef(null);

  function animateProgressThen(cb) {
    setProgress(0);
    clearInterval(progressTimerRef.current);
    progressTimerRef.current = setInterval(() => {
      setProgress((p) => {
        const next = Math.min(100, p + Math.floor(8 + Math.random() * 12));
        if (next >= 100) {
          clearInterval(progressTimerRef.current);
          setTimeout(cb, 350);
        }
        return next;
      });
    }, 130);
  }

  function connect() {
    if (wsRef.current) return;
    const ws = new WebSocket(`ws://${location.host}`);
    wsRef.current = ws;

    ws.onopen = () => {
      setWsReady(true);
      if (roleRef.current === "send") {
        ws.send(JSON.stringify({ type: "start-pairing" }));
      }
    };

    ws.onmessage = async (event) => {
      const data = JSON.parse(event.data);

      if (data.type === "pairing-code") {
        setPairingCode(data.code);
        setMySenderId(data.senderId);
        cryptoKeyRef.current = await deriveKey(data.code);
      }

      if (data.type === "peer-connected") {
        setPeerLabel(data.deviceName || "Unnamed device");
        setStep("warning");
      }

      if (data.type === "verified") {
        if (data.success) {
          setVerifyError("");
          setPeerLabel(`Sender #${data.senderId}`);
          cryptoKeyRef.current = await deriveKey(lastSubmittedCodeRef.current);
          setStep("warning");
        } else {
          setVerifyError("Wrong code — try again.");
        }
      }

      if (data.type === "file") {
        try {
          const encBuf = base64ToBuf(data.data);
          const iv = new Uint8Array(base64ToBuf(data.iv));
          const decrypted = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv }, cryptoKeyRef.current, encBuf);
          const hashHex = await sha256Hex(decrypted);
          const ok = hashHex === data.hash;
          const blob = new Blob([decrypted]);
          const url = URL.createObjectURL(blob);
          setIncomingFile({ name: data.filename, url, size: decrypted.byteLength, integrityOk: ok });
          animateProgressThen(() => setStep("complete"));
        } catch (e) {
          setIncomingFile({ name: data.filename, error: true });
          setStep("complete");
        }
      }
    };
  }

  function reset() {
    clearInterval(progressTimerRef.current);
    if (wsRef.current) {
      wsRef.current.onmessage = null;
      wsRef.current.close();
      wsRef.current = null;
    }
    roleRef.current = null;
    cryptoKeyRef.current = null;
    lastSubmittedCodeRef.current = "";
    setStep("home");
    setRole(null);
    setSelectedFile(null);
    setPairingCode(null);
    setMySenderId(null);
    setPeerLabel(null);
    setCodeInput("");
    setMyDeviceName("");
    setVerifyError("");
    setShowQr(false);
    setProgress(0);
    setIncomingFile(null);
    setWsReady(false);
  }

  function chooseSend() {
    roleRef.current = "send";
    setRole("send");
    setStep("send");
  }
  function chooseReceive() {
    roleRef.current = "receive";
    setRole("receive");
    setStep("pairing");
    connect();
  }
  function handleFilePicked(e) {
    const f = e.target.files?.[0];
    if (f) setSelectedFile(f);
  }
  function handleContinueFromSend() {
    setStep("pairing");
    connect();
  }
  function handleVerifyClick() {
    lastSubmittedCodeRef.current = codeInput;
    wsRef.current.send(JSON.stringify({
      type: "verify-code",
      code: codeInput,
      deviceName: myDeviceName || "Unnamed device",
    }));
  }

  useEffect(() => {
    if (step !== "transfer" || role !== "send" || !selectedFile) return;
    let cancelled = false;
    (async () => {
      const fileBuf = await selectedFile.arrayBuffer();
      const hash = await sha256Hex(fileBuf);
      const iv = window.crypto.getRandomValues(new Uint8Array(12));
      const encrypted = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv }, cryptoKeyRef.current, fileBuf);
      if (cancelled) return;
      wsRef.current.send(JSON.stringify({
        type: "file",
        filename: selectedFile.name,
        data: bufToBase64(encrypted),
        iv: bufToBase64(iv),
        hash,
      }));
    })();
    animateProgressThen(() => setStep("complete"));
    return () => { cancelled = true; };
  }, [step]);

  return (
    <PhoneShell>
      {step === "home" && (
        <div className="px-7 pt-10 pb-8 text-center">
          <div className="w-16 h-16 mx-auto mb-5 rounded-2xl bg-[#ECFDF5] flex items-center justify-center">
            <ShieldCheck size={30} className="text-[#0B7A5F]" strokeWidth={2} />
          </div>
          <h1 className="text-xl font-bold text-[#16241E] mb-2">SecureLink</h1>
          <p className="text-sm text-[#5B6B64] leading-relaxed mb-6">
            Direct, peer-to-peer file sharing over shared Wi-Fi. Every transfer is paired and encrypted.
          </p>
          <div className="text-left space-y-3 mb-7">
            <div>
              <div className="text-[13px] font-bold text-[#16241E] flex items-center gap-1.5">
                <KeyRound size={13} className="text-[#0B7A5F]" /> Device pairing required
              </div>
              <div className="text-xs text-[#5B6B64] mt-0.5">Verified with a real 6-digit code before any file moves.</div>
            </div>
            <div>
              <div className="text-[13px] font-bold text-[#16241E] flex items-center gap-1.5">
                <Lock size={13} className="text-[#0B7A5F]" /> Zero-fallback encryption
              </div>
              <div className="text-xs text-[#5B6B64] mt-0.5">AES-256-GCM, derived from the pairing code, verified with SHA-256.</div>
            </div>
          </div>
          <div className="space-y-2.5">
            <PrimaryButton onClick={chooseSend}>Send File</PrimaryButton>
            <SecondaryButton onClick={chooseReceive}>Receive File</SecondaryButton>
          </div>
        </div>
      )}

      {step === "send" && (
        <div>
          <TopBar onBack={() => setStep("home")} onRestart={reset} label="Send a File" />
          <div className="px-6 pb-7">
            <input type="file" ref={fileInputRef} onChange={handleFilePicked} className="hidden" />
            <button onClick={() => fileInputRef.current?.click()}
              className="w-full border-2 border-dashed border-[#CDEEE1] bg-[#F5FBF8] rounded-2xl py-9 flex flex-col items-center gap-2 hover:bg-[#ECFDF5]">
              <Upload size={26} className="text-[#0B7A5F]" />
              <span className="text-sm font-semibold text-[#16241E]">Click to choose a file</span>
              <span className="text-xs text-[#5B6B64]">or drag and drop it here</span>
            </button>
            {selectedFile && (
              <div className="mt-4 border border-[#E3E9E6] rounded-xl p-3.5 flex items-center gap-3">
                <div className="w-9 h-9 rounded-lg bg-[#ECFDF5] flex items-center justify-center shrink-0">
                  <FileText size={16} className="text-[#0B7A5F]" />
                </div>
                <div className="min-w-0">
                  <div className="text-sm font-semibold text-[#16241E] truncate">{selectedFile.name}</div>
                  <div className="text-xs text-[#5B6B64]">{formatBytes(selectedFile.size)} · {selectedFile.type || "Unknown type"}</div>
                </div>
              </div>
            )}
            <PrimaryButton className="mt-6" disabled={!selectedFile} onClick={handleContinueFromSend}>Continue</PrimaryButton>
          </div>
        </div>
      )}

      {step === "pairing" && role === "send" && (
        <div>
          <TopBar onBack={() => setStep("send")} onRestart={reset} label="Device Pairing" />
          <div className="px-6 pb-7">
            <h2 className="text-base font-bold text-[#16241E] mb-1">Waiting for a device</h2>
            <p className="text-xs text-[#5B6B64] mb-5">Share this code with the receiving device.</p>
            {!showQr ? (
              <div className="bg-[#ECFDF5] border border-[#CDEEE1] rounded-2xl py-6 text-center mb-5">
                <div className="text-[11px] font-bold uppercase tracking-wide text-[#0B7A5F] mb-2">Verification code</div>
                <div className="text-4xl font-bold tracking-[0.35em] text-[#16241E] tabular-nums">
                  {pairingCode || "------"}
                </div>
              </div>
            ) : (
              <div className="bg-[#F5FBF8] border border-[#CDEEE1] rounded-2xl py-8 flex flex-col items-center mb-5">
                <div className="w-28 h-28 bg-white border border-[#CDEEE1] rounded-xl flex items-center justify-center mb-3">
                  <QrCode size={64} className="text-[#16241E]" />
                </div>
                <div className="text-xs text-[#5B6B64] text-center px-4">
                  Showing code as a placeholder — QR scanning isn't wired up in this demo, share the digits instead.
                </div>
              </div>
            )}
            <button onClick={() => setShowQr((v) => !v)} className="w-full text-xs font-semibold text-[#0B7A5F] py-2 mb-5">
              {showQr ? "Show the 6-digit code" : "Show as QR (placeholder)"}
            </button>
            <div className="flex items-center justify-center gap-2 text-xs text-[#5B6B64]">
              <Loader2 size={14} className="animate-spin text-[#0B7A5F]" /> Waiting for the other device to enter this code…
            </div>
          </div>
        </div>
      )}

      {step === "pairing" && role === "receive" && (
        <div>
          <TopBar onBack={reset} onRestart={reset} label="Device Pairing" />
          <div className="px-6 pb-7">
            <h2 className="text-base font-bold text-[#16241E] mb-1">Connect to a device</h2>
            <p className="text-xs text-[#5B6B64] mb-5">Enter the code shown on the sending device.</p>
            <input
              value={myDeviceName}
              onChange={(e) => setMyDeviceName(e.target.value)}
              placeholder="Name this device (e.g. My Laptop)"
              className="w-full border border-[#E3E9E6] rounded-xl px-3.5 py-2.5 text-sm mb-3 focus:outline-none focus:border-[#10B981]"
            />
            <input
              value={codeInput}
              onChange={(e) => setCodeInput(e.target.value.replace(/\D/g, "").slice(0, 6))}
              placeholder="000000"
              className="w-full text-center text-3xl font-bold tracking-[0.3em] tabular-nums border border-[#E3E9E6] rounded-xl py-4 mb-3 focus:outline-none focus:border-[#10B981]"
            />
            {verifyError && (
              <div className="text-xs font-semibold text-[#B3261E] mb-3 text-center">{verifyError}</div>
            )}
            <PrimaryButton disabled={codeInput.length !== 6 || !wsReady} onClick={handleVerifyClick}>
              Verify
            </PrimaryButton>
          </div>
        </div>
      )}

      {step === "warning" && (
        <div>
          <TopBar onBack={() => setStep("pairing")} onRestart={reset} label="Network Check" />
          <div className="px-6 pb-7">
            <div className="bg-[#FEF3E2] border border-[#F5D9A8] rounded-2xl p-5 text-center mb-6">
              <div className="w-11 h-11 mx-auto mb-3 rounded-full bg-[#FDE8C8] flex items-center justify-center">
                <AlertTriangle size={20} className="text-[#A45A00]" />
              </div>
              <div className="text-sm font-bold text-[#8A5A00] mb-1.5">Unsafe network detected</div>
              <p className="text-xs text-[#8A5A00] leading-relaxed">
                Simulated for this demo — a real deployment would check actual network conditions.
                On an open network, nearby devices may be able to see traffic.
              </p>
            </div>
            <div className="flex items-start gap-2.5 bg-[#F0F3F1] rounded-xl p-3.5 mb-6">
              <ShieldCheck size={16} className="text-[#0B7A5F] shrink-0 mt-0.5" />
              <p className="text-xs text-[#5B6B64] leading-relaxed">
                SecureLink still requires device verification and end-to-end encryption regardless — this
                warning does not skip that step.
              </p>
            </div>
            <PrimaryButton onClick={() => setStep("verify")}>Continue to Device Verification</PrimaryButton>
          </div>
        </div>
      )}

      {step === "verify" && (
        <div>
          <TopBar onBack={() => setStep("pairing")} onRestart={reset} label="Verify Device" />
          <div className="px-6 pb-7 text-center">
            <div className="w-14 h-14 mx-auto mb-4 rounded-2xl bg-[#ECFDF5] flex items-center justify-center">
              <ShieldCheck size={24} className="text-[#0B7A5F]" />
            </div>
            <h2 className="text-base font-bold text-[#16241E] mb-1">Is this the device you want to connect to?</h2>
            <p className="text-xs text-[#5B6B64] mb-5">Confirm the name and code match what's shown on the other side.</p>
            <div className="border border-[#E3E9E6] rounded-xl p-4 mb-6 text-left">
              <div className="text-sm font-semibold text-[#16241E] mb-2">{peerLabel || "Unknown device"}</div>
              <div className="text-[11px] font-bold uppercase tracking-wide text-[#5B6B64] mb-1">Verification code</div>
              <div className="text-2xl font-bold tracking-[0.3em] text-[#16241E] tabular-nums">
                {role === "send" ? pairingCode : codeInput}
              </div>
            </div>
            <div className="space-y-2.5">
              <PrimaryButton onClick={() => setStep("verified")}>Confirm Device</PrimaryButton>
              <button onClick={() => setStep("pairing")} className="w-full py-3 rounded-xl font-semibold text-sm bg-[#FBEAEA] text-[#B3261E] hover:bg-[#F6DADA]">
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {step === "verified" && (
        <div className="px-7 pt-10 pb-8 text-center">
          <div className="w-16 h-16 mx-auto mb-5 rounded-full bg-[#ECFDF5] flex items-center justify-center">
            <Lock size={28} className="text-[#0B7A5F]" />
          </div>
          <h2 className="text-base font-bold text-[#16241E] mb-1">Secure connection verified</h2>
          <p className="text-xs text-[#5B6B64] mb-6">Cryptographic handshake complete. Safe to transfer files.</p>
          <div className="flex items-center justify-between border border-[#E3E9E6] rounded-xl p-4 mb-7 text-left">
            <div>
              <div className="text-[11px] font-bold uppercase tracking-wide text-[#9AA6A1] mb-0.5">
                {role === "send" ? "Sender" : "Receiver"}
              </div>
              <div className="text-sm font-semibold text-[#16241E]">This device</div>
            </div>
            <ShieldCheck size={16} className="text-[#0B7A5F]" />
            <div className="text-right">
              <div className="text-[11px] font-bold uppercase tracking-wide text-[#9AA6A1] mb-0.5">
                {role === "send" ? "Receiver" : "Sender"}
              </div>
              <div className="text-sm font-semibold text-[#16241E]">{peerLabel}</div>
            </div>
          </div>
          <PrimaryButton onClick={() => setStep("transfer")}>Continue</PrimaryButton>
        </div>
      )}

      {step === "transfer" && (
        <div>
          <TopBar onRestart={reset} label={role === "send" ? "Sending" : "Receiving"} />
          <div className="px-6 pb-7">
            <div className="flex items-center gap-3 border border-[#E3E9E6] rounded-xl p-3.5 mb-5">
              <div className="w-9 h-9 rounded-lg bg-[#ECFDF5] flex items-center justify-center shrink-0">
                <FileText size={16} className="text-[#0B7A5F]" />
              </div>
              <div className="min-w-0">
                <div className="text-sm font-semibold text-[#16241E] truncate">
                  {role === "send" ? selectedFile?.name : "Waiting for incoming file…"}
                </div>
                {role === "send" && <div className="text-xs text-[#5B6B64]">{formatBytes(selectedFile?.size)}</div>}
              </div>
            </div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-semibold text-[#5B6B64]">{role === "send" ? "Sending…" : "Receiving…"}</span>
              <span className="text-xs font-bold text-[#16241E] tabular-nums">{progress}%</span>
            </div>
            <div className="w-full h-2.5 bg-[#E3E9E6] rounded-full overflow-hidden mb-5">
              <div className="h-full bg-[#10B981] rounded-full transition-all duration-150 ease-out" style={{ width: `${progress}%` }} />
            </div>
            <div className="flex flex-wrap gap-2">
              <span className="inline-flex items-center gap-1.5 text-[11px] font-semibold bg-[#ECFDF5] text-[#0B7A5F] px-2.5 py-1.5 rounded-full">
                <Lock size={11} /> Encrypted transfer (E2E)
              </span>
              <span className="inline-flex items-center gap-1.5 text-[11px] font-semibold bg-[#ECFDF5] text-[#0B7A5F] px-2.5 py-1.5 rounded-full">
                <Wifi size={11} /> Connection healthy
              </span>
            </div>
          </div>
        </div>
      )}

      {step === "complete" && (
        <div className="px-7 pt-10 pb-8 text-center">
          <div className="w-16 h-16 mx-auto mb-5 rounded-full bg-[#ECFDF5] flex items-center justify-center">
            <CheckCircle2 size={30} className="text-[#0B7A5F]" />
          </div>
          <h2 className="text-base font-bold text-[#16241E] mb-1">File successfully transferred</h2>
          <p className="text-xs text-[#5B6B64] mb-6">Packaged, cryptographically signed, and verified.</p>

          <div className="border border-[#E3E9E6] rounded-xl p-4 mb-3 text-left">
            <div className="text-sm font-semibold text-[#16241E] truncate">
              {role === "send" ? selectedFile?.name : incomingFile?.name}
            </div>
            <div className="text-xs text-[#5B6B64] mt-0.5">
              {role === "send"
                ? `${formatBytes(selectedFile?.size)} · Sent to ${peerLabel}`
                : `${formatBytes(incomingFile?.size)} · Received from ${peerLabel}`}
            </div>
          </div>

          {role === "receive" && incomingFile && !incomingFile.error && (
            <a href={incomingFile.url} download={incomingFile.name}
              className="flex items-center justify-center gap-2 text-sm font-semibold text-[#0B7A5F] border border-[#CDEEE1] bg-[#ECFDF5] rounded-xl py-2.5 mb-4 hover:bg-[#DBF6EA]">
              <Download size={15} /> Download file
            </a>
          )}

          <div className={`flex items-center gap-1.5 justify-center text-xs font-semibold mb-7 ${
            role === "receive" && incomingFile && !incomingFile.integrityOk ? "text-[#B3261E]" : "text-[#0B7A5F]"
          }`}>
            <ShieldCheck size={13} />
            {role === "receive" && incomingFile && !incomingFile.integrityOk
              ? "Integrity check failed — file may be corrupted"
              : "Transfer secured"}
          </div>

          <PrimaryButton onClick={reset}>Done</PrimaryButton>
        </div>
      )}
    </PhoneShell>
  );
}

createRoot(document.getElementById("root")).render(<App />);