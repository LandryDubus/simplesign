# Corpus CAdES/XAdES do EU DSS

Os arquivos deste diretório são vetores externos de interoperabilidade, obtidos do
repositório [EU DSS](https://github.com/esig/dss) no commit indicado em `manifest.json`.
O EU DSS é licenciado sob LGPL-2.1-or-later; os arquivos são preservados sem alteração.

Cada teste valida o SHA-256 antes de usar o artefato. Isso torna qualquer atualização
explícita e reproduzível: obtenha o mesmo commit, substitua o arquivo, atualize o hash e
registre o motivo da atualização no manifesto.

Os arquivos `.content` de CAdES foram extraídos uma única vez do `SignedData` anexado pelo
comando `openssl cms -verify -inform DER -noverify`; eles permitem que o validador local
verifique o `messageDigest` sem rede. O XML `xades-detached-content.xml` é o documento
externo original fornecido pelo próprio corpus EU DSS.

Os vetores B-LTA externos são testes positivos de interoperabilidade para
`ATSHashIndexV3`/`ArchiveTimeStamp` e também incluem mutações negativas. O resultado
positivo confirma a cobertura ETSI; o vetor modificado ou com token copiado deve resultar
em `false`, nunca em falso positivo.

Da mesma forma, `xades-blt-enveloped.xml` é um B-T com `TimeStampValidationData` para a TSA,
e não é aceito como prova de LTV completa da assinatura. O teste protege essa distinção até
que o validador tenha um ledger de material por caminho de certificado.
