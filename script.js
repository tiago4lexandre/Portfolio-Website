const content = document.getElementById('content');
const menuToggle = document.querySelector('.menu-toggle');
const menu = document.querySelector('.menu');

const data = {
	checklists: [
		{ title: 'Pentest Checklist', file: 'Checklists/Pentest-Checklist/README.md', slug: 'pentest-checklist' },
		{ title: 'Local File Inclusion e Remote File Inclusion', file: 'Checklists/LFI-RFI/README.md', slug: 'lfi-rfi' },
	],
	cves: [
		{ title: 'React2Shell — CVE-2025-55182', file: 'Vulnerabilidades/React2Shell/README.md', slug: 'react2shell' },
		{ title: 'Dirty Pipe — CVE-2022-0847', file: 'Vulnerabilidades/DirtyPipez/README.md', slug: 'dirty-pipe' },
		{ title: 'Pwnkit — CVE-2021-4034', file: 'Vulnerabilidades/Pwnkit/README.md', slug: 'pwnkit' },
	],
	linux: [
		{ title: 'Linux Privilege Escalation', file: 'Linux/Linux-Privilege-Escalation/README.md', slug: 'linux-privilege-escalation' },
		{ title: 'Stable Reverse Shell', file: 'Linux/Stable-ReverseShell/README.md', slug: 'stable-reverse-shell' },
	],
	windows: [
		{ title: 'Windows Privilege Escalation', file: 'Windows/Windows-PrivilegeEscalation/README.md', slug: 'windows-privilege-escalation' },
		{ title: 'EternalBlue — MS17-010', file: 'Windows/EternalBlue/README.md', slug: 'eternalblue' },
	],
	network: [
		{ title: 'ARP Spoofing & MITM', file: 'Network/ARP-Spoofing-MITM/README.md', slug: 'arp-spoofing-mitm' },
	],
	tools: [
		{ title: 'Gobuster', file: 'Ferramentas/GoBuster/README.md', slug: 'gobuster' },
		{ title: 'FFUF', file: 'Ferramentas/FFUF/README.md', slug: 'ffuf' },
		{ title: 'Hydra', file: 'Ferramentas/Hydra/README.md', slug: 'hydra' },
		{ title: 'John The Ripper', file: 'Ferramentas/John-The-Ripper/README.md', slug: 'john-the-ripper' },
	],
	labs: [
		{ title: 'Linux Privilege Escalation — TryHackMe', file: 'Laboratorios/THM-LinuxPrivilegeEscalation/README.md', slug: 'thm-linux-privilege-escalation' },
		{ title: 'Mr. Robot — TryHackMe', file: 'Laboratorios/THM-MrRobot/README.md', slug: 'thm-mr-robot' },
		{ title: 'Gallery — TryHackMe', file: 'Laboratorios/THM-Gallery/README.md', slug: 'thm-gallery' },
		{ title: 'Break Out The Cage — TryHackMe', file: 'Laboratorios/THM-BreakOutTheCage/README.md', slug: 'thm-break-out-the-cage' },
		{ title: 'PwnLab: Init', file: 'Laboratorios/PWNLAB/README.md', slug: 'pwnlab-init' },
	],
};

// Função para alternar menu no mobile
function toggleMenu() {
	if (menu) {
		menu.classList.toggle('open');
		
		// Atualiza o texto do botão
		if (menu.classList.contains('open')) {
			menuToggle.textContent = '✕ Fechar';
		} else {
			menuToggle.textContent = '☰ Menu';
		}
	}
}

// Fecha o menu ao clicar em um item (para mobile)
function closeMenu() {
	if (window.innerWidth <= 768) {
		menu.classList.remove('open');
		menuToggle.textContent = '☰ Menu';
	}
}

// Função para corrigir imagens após o carregamento
function fixImages() {
	const images = document.querySelectorAll('#content img');
	
	images.forEach(img => {
		// Remove qualquer width/height inline que possa estar causando problemas
		img.removeAttribute('width');
		img.removeAttribute('height');
		
		// Força estilos para garantir responsividade
		img.style.maxWidth = '100%';
		img.style.height = 'auto';
		img.style.display = 'block';
		img.style.marginLeft = 'auto';
		img.style.marginRight = 'auto';
		
		// Adiciona atributo loading lazy para performance
		if (!img.hasAttribute('loading')) {
			img.setAttribute('loading', 'lazy');
		}
		
		// Adiciona alt se não existir
		if (!img.hasAttribute('alt')) {
			img.setAttribute('alt', 'Imagem de documento de segurança');
		}
	});
}

function loadHome() {
	document.title = 'Tiago | Cybersecurity Portfolio';

	content.innerHTML = `
		<h1>Olá, eu sou o Tiago 👋</h1>

		<p>
			Estudante de <strong>Engenharia de Software</strong> com foco em
			<strong>Cibersegurança</strong>, especialmente em segurança ofensiva,
			análise de vulnerabilidades, aplicações web, redes e ambientes Linux.
		</p>

		<p>
			Este site funciona como meu <strong>portfólio técnico</strong>, onde organizo
			documentações de estudo, análises de <strong>CVEs reais</strong>,
			laboratórios práticos de pentest e anotações técnicas.
		</p>

		<hr />

		<h2>🛠️ Ferramentas e Tecnologias</h2>
		<ul>
			<li><strong>Sistemas:</strong> Linux, Windows</li>
			<li><strong>Web:</strong> HTTP, REST, Next.js, React</li>
			<li><strong>Linguagens:</strong> Python, Bash, JavaScript, C, Java</li>
			<li><strong>Ferramentas:</strong> Nmap, Burp Suite, Gobuster, FFUF, Hydra, SQLMap, Metasploit</li>
			<li><strong>Ambientes:</strong> TryHackMe, VulnHub, Labs locais</li>
		</ul>

		<hr />

		<h2>📫 Contato</h2>
		<ul>
			<li>🔗 <a href="https://www.linkedin.com/in/tiago-alexandre2001" target="_blank">LinkedIn</a></li>
			<li>💻 <a href="https://github.com/tiago4lex" target="_blank">GitHub</a></li>
		</ul>

		<footer>
			Conteúdo educacional • Ambientes autorizados • © Tiago Alexandre
		</footer>
	`;
	
	// Fecha menu se estiver aberto (mobile)
	closeMenu();
}

function navigateCategory(category) {
	location.hash = `/${category}`;
	closeMenu();
}

function navigateTo(category, slug) {
	location.hash = `/${category}/${slug}`;
	closeMenu();
}

function router() {
	const hash = location.hash.replace('#', '');

	if (!hash || hash === '/') {
		loadHome();
		return;
	}

	const parts = hash.split('/').filter(Boolean);

	// /categoria
	if (parts.length === 1) {
		const category = parts[0];
		loadCategory(category);
		return;
	}

	// /categoria/slug
	if (parts.length === 2) {
		const [category, slug] = parts;

		const item = data[category]?.find(doc => doc.slug === slug);

		if (!item) {
			content.innerHTML = '<h2>Documento não encontrado</h2>';
			return;
		}

		document.title = `${item.title} | Tiago Cybersecurity`;
		loadMarkdown(item.file);
	}
}

function loadCategory(category) {
	const items = data[category];

	if (!items) {
		content.innerHTML = '<h2>Categoria não encontrada</h2>';
		return;
	}

	document.title = `${category.toUpperCase()} | Tiago Cybersecurity`;

	let html = `<h2>${category.toUpperCase()}</h2><div class="doc-list">`;

	items.forEach(item => {
		html += `
			<div class="doc-item" onclick="navigateTo('${category}', '${item.slug}')">
				${item.title}
			</div>
		`;
	});

	html += '</div>';
	content.innerHTML = html;
	
	closeMenu();
}

async function loadMarkdown(path) {
	content.innerHTML = '<p>Carregando documentação...</p>';

	try {
		const res = await fetch(path);
		let markdown = await res.text();

		const basePath = path.substring(0, path.lastIndexOf('/') + 1);

		markdown = markdown.replace(
			/!\[(.*?)\]\((?!http)(.*?)\)/g,
			(_, alt, src) => `![${alt}](${basePath}${src})`
		);

		content.innerHTML = marked.parse(markdown);
		
		// Corrige as imagens após carregar o conteúdo
		setTimeout(fixImages, 100);
	} catch {
		content.innerHTML = '<p>Erro ao carregar o documento.</p>';
	}
	
	closeMenu();
}

// Event Listeners
window.addEventListener('hashchange', router);

// Fecha menu ao clicar fora (para mobile)
document.addEventListener('click', (event) => {
	if (window.innerWidth <= 768 && menu && menuToggle) {
		const isClickInsideMenu = menu.contains(event.target);
		const isClickOnToggle = menuToggle.contains(event.target);
		
		if (!isClickInsideMenu && !isClickOnToggle && menu.classList.contains('open')) {
			closeMenu();
		}
	}
});

// Fecha menu ao redimensionar a janela se voltar para desktop
window.addEventListener('resize', () => {
	if (window.innerWidth > 768 && menu) {
		menu.classList.remove('open');
		if (menuToggle) {
			menuToggle.textContent = '☰ Menu';
		}
	}
});

// Inicializa o router
router();

// Configura os botões do menu para fechar no mobile
document.querySelectorAll('.menu button').forEach(button => {
	button.addEventListener('click', closeMenu);

});
