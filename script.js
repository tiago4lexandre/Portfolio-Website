const content = document.getElementById('content');

const data = {
	checklists: [
		{ title: 'Pentest Checklist', file: 'Pentest-Checklist/README.md' },
	],
	cves: [
		{ title: 'React2Shell — CVE-2025-55182', file: 'React2Shell/README.md' },
		{ title: 'Dirty Pipe — CVE-2022-0847', file: 'Dirty-Pipe-CVE-2022-0847/README.md',
		},
	],
	linux: [
		{ title: 'Linux Privilege Escalation', file: 'Linux-Privilege-Escalation/README.md',
		},
		{ title: 'Stable Reverse Shell', file: 'Stable-ReverseShell/README.md' },
	],
	network: [
		{ title: 'ARP Spoofing & MITM', file: 'ARP-Spoofing-MITM/README.md' },
	],
	tools: [
		{ title: 'Gobuster', file: 'GoBuster/README.md' },
		{ title: 'Hydra', file: 'Hydra/README.md' },
		{ title: 'John The Ripper', file: 'John-The-Ripper/README.md' },
	],
	labs: [
		{ title: 'Mr. Robot — TryHackMe', file: 'Mr-Robot/README.md' },
		{ title: 'Gallery — TryHackMe', file: 'Gallery/README.md' },
		{ title: 'PwnLab: Init', file: 'PWNLAB/README.md' },
	],
};

function loadHome() {
	content.innerHTML = `
        <h1>Olá, eu sou o Tiago 👋</h1>
        <p>
          Estudante de Engenharia de Software com foco em <strong>Cibersegurança</strong>,
          segurança ofensiva, análise de vulnerabilidades, ambientes Linux e redes.
        </p>
        <p>
          Este site funciona como meu <strong>portfólio técnico</strong>, onde organizo
          documentações, CVEs analisadas, laboratórios práticos e estudos aprofundados.
        </p>
        <p>
          Use o menu lateral para navegar entre os conteúdos.
        </p>
        <footer>
          Conteúdo educacional • Ambientes autorizados • © Tiago Alexandre
        </footer>
      `;
}

function loadCategory(category) {
	const items = data[category];

	let html = `<h2>${category.toUpperCase()}</h2><div class="doc-list">`;

	items.forEach((item) => {
		html += `
          <div class="doc-item" onclick="loadMarkdown('${item.file}')">
            ${item.title}
          </div>
        `;
	});

	html += '</div>';
	content.innerHTML = html;
}

async function loadMarkdown(path) {
	content.innerHTML = '<p>Carregando documentação...</p>';

	try {
		const res = await fetch(path);
		const text = await res.text();

		// Conversão simples Markdown → HTML
		const html = text
			.replace(/^### (.*$)/gim, '<h3>$1</h3>')
			.replace(/^## (.*$)/gim, '<h2>$1</h2>')
			.replace(/^# (.*$)/gim, '<h1>$1</h1>')
			.replace(/\*\*(.*)\*\*/gim, '<strong>$1</strong>')
			.replace(/\*(.*)\*/gim, '<em>$1</em>')
			.replace(/`([^`]+)`/gim, '<code>$1</code>')
			.replace(/\n$/gim, '<br />');

		content.innerHTML = html;
	} catch (e) {
		content.innerHTML = '<p>Erro ao carregar o documento.</p>';
	}
}

loadHome();
