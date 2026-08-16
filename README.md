# cert-inventory

<img width="1131" height="742" alt="image" src="https://github.com/user-attachments/assets/509d1fae-1292-43e6-8fda-c13da30ba0fb" />


Inventário de certificados TLS via **Certificate Transparency** (crt.sh), agrupado pela Autoridade Certificadora (CA) que os emitiu.

Consulta os logs públicos de CT para um ou mais domínios, identifica **quem emitiu cada certificado**, o **status de validade** (válido / expira em breve / vencido) e gera um **painel HTML** self-contained para visualização.

## Recursos

- Consulta o crt.sh para todos os subdomínios de um ou mais domínios
- Agrupa os certificados pela CA emissora (Let's Encrypt, DigiCert, Amazon, GlobalSign, etc.)
- Classifica por status: válido, expira em menos de 30 dias, ou vencido
- Deduplicação por ID do certificado
- Exportação para **CSV**
- Painel **HTML** self-contained (sem CDN, roda offline) com:
  - KPIs (total de certificados, nº de CAs, expirando, vencidos)
  - Distribuição por CA
  - Saúde da carteira (donut de status)
  - Horizonte de renovação (expirações por mês)
  - Tabela com busca, filtro por status e ordenação

## Requisitos

- Python 3.8+
- Apenas biblioteca padrão (sem dependências externas)

## Uso

```bash
# Um ou mais domínios
python3 cert-inventory.py exemplo.com.br exemplo.com.ar

# A partir de um arquivo (um domínio por linha)
python3 cert-inventory.py -f dominios.txt

# Gerar painel HTML + CSV, apenas certificados válidos
python3 cert-inventory.py -f dominios.txt --ativos --html painel.html --csv certs.csv
```

### Opções

| Flag        | Descrição                                            |
|-------------|------------------------------------------------------|
| `-f`, `--file` | Arquivo com um domínio por linha                  |
| `--ativos`  | Considera apenas certificados válidos (não vencidos) |
| `--csv`     | Exporta os certificados para CSV                      |
| `--html`    | Gera o painel HTML                                    |
| `--sleep`   | Pausa entre domínios, em segundos (rate limit)       |

## Observação

Certificate Transparency mostra o que foi **emitido**, não necessariamente o que está **instalado** nos hosts. Para um inventário completo, vale complementar com uma varredura ativa da porta 443 e comparar a CA real com a registrada no CT log.

## Créditos

Desenvolvido por **Gabriel Shimbo**, com auxílio de IA.

Fonte de dados: [crt.sh](https://crt.sh) (Certificate Transparency).
