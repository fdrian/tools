async function extractDomains(text) {
  const domainSet = new Set();
  
  // Regex melhorado para capturar URLs completas e domínios/subdomínios
  const urlRegex = /(?:https?:\/\/)?(?:www\.)?([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,})/gi;
  
  // Regex adicional para capturar domínios que podem estar sem protocolo
  const domainRegex = /\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,})\b/g;

  let match;
  
  // Extrai URLs completas
  while ((match = urlRegex.exec(text)) !== null) {
    const domain = match[1].toLowerCase();
    domainSet.add(domain);
  }
  
  // Reset regex
  domainRegex.lastIndex = 0;
  
  // Extrai domínios adicionais que podem não ter protocolo
  while ((match = domainRegex.exec(text)) !== null) {
    const domain = match[1].toLowerCase();
    // Filtra alguns falsos positivos comuns
    if (!domain.includes('.exe') && 
        !domain.includes('.dll') && 
        !domain.includes('.zip') && 
        !domain.includes('.pdf') &&
        !domain.includes('.jpg') &&
        !domain.includes('.png') &&
        !domain.includes('.gif') &&
        domain.split('.').length >= 2) {
      domainSet.add(domain);
    }
  }

  return domainSet;
}

function isValidURL(string) {
  try {
    new URL(string);
    return true;
  } catch (_) {
    return false;
  }
}

async function fetchAndExtractDomains(url) {
  try {
    // Adiciona protocolo se não existir
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      url = 'https://' + url;
    }
    
    const response = await fetch(url);
    const html = await response.text();
    
    // Remove tags HTML e scripts para melhor extração
    const cleanText = html.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
                          .replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, '')
                          .replace(/<[^>]*>/g, ' ')
                          .replace(/&[^;]+;/g, ' ');
    
    return await extractDomains(cleanText);
  } catch (err) {
    console.error("Fetch failed:", err);
    alert("Failed to fetch the URL. This might be due to CORS restrictions or invalid URL format.");
    return new Set();
  }
}

document.getElementById("extract-btn").addEventListener("click", async () => {
  const input = document.getElementById("input-text").value.trim();
  const outputElement = document.getElementById("output-text");
  
  if (!input) {
    alert("Por favor, insira algum texto ou URL para extrair domínios.");
    return;
  }
  
  // Mostra indicador de carregamento
  outputElement.value = "Extraindo domínios...";
  
  let finalSet = new Set();

  if (isValidURL(input)) {
    const fromURL = await fetchAndExtractDomains(input);
    fromURL.forEach(domain => finalSet.add(domain));
  } else {
    const fromText = await extractDomains(input);
    fromText.forEach(domain => finalSet.add(domain));
  }

  const output = Array.from(finalSet).sort();
  
  if (output.length === 0) {
    outputElement.value = "Nenhum domínio encontrado no texto fornecido.";
  } else {
    outputElement.value = output.join("\n");
    console.log(`Encontrados ${output.length} domínios únicos.`);
  }
});

document.getElementById("clear-btn").addEventListener("click", () => {
  document.getElementById("input-text").value = "";
  document.getElementById("output-text").value = "";
});

document.getElementById("copy-btn").addEventListener("click", () => {
  const output = document.getElementById("output-text");
  output.select();
  document.execCommand("copy");
});
