const xssPayloads = [
  '<script>alert(1)</script>',
  '<img src=x onerror=alert(1)>',
  '<svg onload=alert(1)>'
];

const reflectPatterns = xssPayloads.map(p =>
  new RegExp(p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i')
);

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function getParams(url) {
  const params = {};
  const urlObj = new URL(url);
  for (const [key, value] of urlObj.searchParams.entries()) {
    params[key] = value;
  }
  return params;
}

async function isPayloadReflected(body, patterns) {
  return patterns.some(pattern => pattern.test(body));
}

async function testUrlParams(url) {
  const params = getParams(url);
  const findings = [];

  if (Object.keys(params).length === 0) {
    console.log("No query parameters to test.");
    return findings;
  }

  for (const param in params) {
    for (const payload of xssPayloads) {
      const urlObj = new URL(url);
      urlObj.searchParams.set(param, payload);

      console.log(`Testing param "${param}" with payload "${payload}"`);

      try {
        const response = await fetch(urlObj.toString());
        const body = await response.text();

        if (await isPayloadReflected(body, reflectPatterns)) {
          findings.push({
            endpoint: urlObj.toString(),
            param,
            payload,
            evidence: 'Payload reflected in response'
          });
        }
        await sleep(100);
      } catch (e) {
        console.error(`Request failed: ${e.message} for URL: ${urlObj.toString()}`);
      }
    }
  }
  return findings;
}

async function getForms(url) {
  // Get HTML content and parse forms (simplified)
  // For complex parsing, using DOMParser in browser or parsing library in Node is recommended
  const response = await fetch(url);
  const html = await response.text();
  const parser = new DOMParser();
  const doc = parser.parseFromString(html, 'text/html');
  return Array.from(doc.forms);
}

async function testForms(url) {
  const findings = [];
  try {
    const forms = await getForms(url);

    for (const form of forms) {
      const action = form.action || url;
      const method = (form.method || 'GET').toUpperCase();

      // Build default form data
      const formData = {};
      for (const element of form.elements) {
        if (element.name) {
          formData[element.name] = element.value || 'test';
        }
      }

      for (const inputName in formData) {
        for (const payload of xssPayloads) {
          const testData = { ...formData };
          testData[inputName] = payload;

          console.log(`Testing form action "${action}" method "${method}" input "${inputName}" with payload "${payload}"`);

          try {
            let response;
            if (method === 'POST') {
              response = await fetch(action, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: new URLSearchParams(testData).toString()
              });
            } else {
              // GET with params in URL
              const getUrl = new URL(action);
              Object.entries(testData).forEach(([k, v]) => getUrl.searchParams.set(k, v));
              response = await fetch(getUrl.toString());
            }

            const body = await response.text();

            if (await isPayloadReflected(body, reflectPatterns)) {
              findings.push({
                endpoint: action,
                param: inputName,
                payload,
                evidence: 'Payload reflected in response'
              });
            }

            await sleep(100);
          } catch (e) {
            console.error(`Form request failed: ${e.message} for action: ${action}`);
          }
        }
      }
    }
  } catch (e) {
    console.error(`Failed to get forms from ${url}: ${e.message}`);
  }
  return findings;
}

async function runScan(urls) {
  let allFindings = [];

  for (const url of urls) {
    console.log(`Scanning URL parameters on: ${url}`);
    const paramFindings = await testUrlParams(url);
    allFindings = allFindings.concat(paramFindings);

    console.log(`Scanning forms on: ${url}`);
    const formFindings = await testForms(url);
    allFindings = allFindings.concat(formFindings);
  }

  return allFindings;
}

// Example usage:
const targetUrls = ['http://localhost:8080/vulnerabilities/reflected/?q=test'];

runScan(targetUrls).then(findings => {
  console.log('Scan completed. Findings:', findings);
});
