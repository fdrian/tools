// URL Debugger – encode/decode percent-encoding
document.addEventListener('DOMContentLoaded', () => {
    const $in   = document.getElementById('input-text');
    const $out  = document.getElementById('output-text');
    const copyBtn   = document.getElementById('copy-btn');
    const clearBtn  = document.getElementById('clear-btn');
    const encodeBtn = document.getElementById('encode-btn');
    const decodeBtn = document.getElementById('decode-btn');
    const liveToggle = document.getElementById('live-toggle');
    const liveModeSelect = document.getElementById('live-mode-select');

    function updateLiveResult() {
        const mode = liveModeSelect.value;
        const text = $in.value;
        if (mode === 'encode') {
            $out.value = encodeURIComponent(text);
        } else if (mode === 'decode') {
            try {
                $out.value = decodeURIComponent(text.replace(/\+/g, '%20'));
            } catch {
                $out.value = '⚠️ Invalid percent-encoding';
            }
        }
    }

    $in.addEventListener('input', () => {
        if (liveToggle.checked) updateLiveResult();
    });

    liveToggle.addEventListener('change', () => {
        liveModeSelect.disabled = !liveToggle.checked;
        if (liveToggle.checked) updateLiveResult();
    });

    liveModeSelect.addEventListener('change', () => {
        if (liveToggle.checked) updateLiveResult();
    });


    // Atualiza ano no footer
    document.getElementById('current-year').textContent = new Date().getFullYear();

    encodeBtn.addEventListener('click', () => {
        $out.value = encodeURIComponent($in.value);
    });

    decodeBtn.addEventListener('click', () => {
        try {
            $out.value = decodeURIComponent($in.value.replace(/\+/g, '%20'));
        } catch (err) {
            $out.value = '⚠️ Invalid percent-encoding';
        }
    });

    clearBtn.addEventListener('click', () => {
        $in.value = '';
        $out.value = '';
    });

    copyBtn.addEventListener('click', async () => {
        if (!$out.value) return;
        try {
            await navigator.clipboard.writeText($out.value);
            copyBtn.textContent = 'Copied!';
            setTimeout(() => copyBtn.textContent = 'Copy Result', 2000);
        } catch { /* fallback silencioso */ }
    });
});
