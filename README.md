# Brute Force DNS Server
Modo de usar:
python3 dns_bruteforce.py [SITE] [WORDLIST.TXT]

Um Brute Force DNS Server não é um conceito padrão ou amplamente reconhecido na área de redes ou segurança da informação. No entanto, podemos interpretar esse termo com base em conceitos relacionados, como ataques de força bruta e servidores DNS.

1. Ataque de Força Bruta (Brute Force Attack)
Um ataque de força bruta é uma técnica em que um invasor tenta adivinhar uma senha, chave ou outra informação confidencial testando todas as combinações possíveis até encontrar a correta.

Esse método é demorado e computacionalmente intensivo, mas pode ser eficaz se a senha ou chave for fraca.

2. Servidor DNS
Um servidor DNS (Domain Name System) é responsável por traduzir nomes de domínio (como www.exemplo.com) em endereços IP (como 192.168.1.1), permitindo que os dispositivos se conectem uns aos outros na internet.

Interpretação de "Brute Force DNS Server"
Um Brute Force DNS Server poderia se referir a um servidor DNS que está sendo alvo de um ataque de força bruta. Por exemplo, um invasor pode tentar adivinhar subdomínios de um domínio específico (um ataque conhecido como DNS Brute Forcing ou Subdomain Enumeration).

Alternativamente, poderia se referir a um servidor DNS malicioso configurado para realizar ataques de força bruta contra outros sistemas, como tentar resolver nomes de domínio de forma massiva para descobrir subdomínios válidos.

Ataques de Força Bruta em DNS
Enumeração de Subdomínios: Um invasor pode usar ferramentas como dnsenum, sublist3r ou amass para tentar descobrir subdomínios válidos de um domínio, testando uma lista de possíveis nomes (por exemplo, admin.exemplo.com, test.exemplo.com, etc.).

Amplificação de DNS: Embora não seja exatamente um ataque de força bruta, um invasor pode explorar servidores DNS mal configurados para amplificar ataques DDoS, enviando consultas DNS falsificadas para gerar tráfego massivo.