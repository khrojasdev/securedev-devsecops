// =============================================================================
// SecureDev - Pipeline CI/CD con seguridad integrada (DevSecOps)
// Etapas: Checkout -> Build -> Pruebas -> SAST -> SCA (dependencias) ->
//         Deploy Staging -> DAST (OWASP ZAP) -> Documentacion/Trazabilidad ->
//         Deploy Produccion -> Monitorizacion (Prometheus/Grafana)
// Requisitos del agente: Docker CLI con acceso al daemon (jenkins/Dockerfile).
// =============================================================================
pipeline {
    agent any

    parameters {
        booleanParam(name: 'ENFORCE_GATES', defaultValue: true,
            description: 'Si es true, un hallazgo de seguridad DETIENE el pipeline. Usar false solo para documentar la linea base vulnerable.')
        choice(name: 'ZAP_SCAN', choices: ['full', 'baseline'],
            description: 'full = escaneo activo (ataca la app en staging); baseline = solo pasivo')
        string(name: 'SCAN_USER', defaultValue: 'kevin', description: 'Usuario para el escaneo autenticado de ZAP')
        password(name: 'SCAN_PASSWORD', defaultValue: 'Kev1n!SecureDev-2026', description: 'Contrasena del usuario de escaneo (staging)')
        booleanParam(name: 'DEPLOY_PROD', defaultValue: true, description: 'Desplegar a produccion si todos los controles pasan')
    }

    options {
        timestamps()
        buildDiscarder(logRotator(numToKeepStr: '20'))
        timeout(time: 60, unit: 'MINUTES')
        disableConcurrentBuilds()
    }

    environment {
        APP        = 'securedev'
        IMAGE      = "securedev:${env.BUILD_NUMBER}"
        TEST_IMAGE = "securedev-test:${env.BUILD_NUMBER}"
        NET        = 'securedev-net'
        STAGING    = 'securedev-staging'
        PROD       = 'securedev-prod'
        ZAP_IMAGE  = 'ghcr.io/zaproxy/zaproxy:stable'
        // Secreto de la app guardado en Jenkins > Credentials (Secret text)
        SECRET_KEY = credentials('securedev-secret-key')
    }

    stages {

        stage('Checkout') {
            steps {
                checkout scm
                sh '''
                    mkdir -p reports/zap
                    git log -1 --format="Commit %H | %an | %ad | %s" | tee reports/commit.txt
                '''
            }
        }

        stage('Build') {
            steps {
                sh '''
                    docker build --pull --target test    -t "$TEST_IMAGE" .
                    docker build --pull --target runtime -t "$IMAGE" -t securedev:latest .
                    docker image inspect "$IMAGE" --format "Imagen {{.Id}} creada {{.Created}}" | tee reports/image.txt
                '''
            }
        }

        stage('Pruebas unitarias y de seguridad') {
            steps {
                script {
                    def rc = runInTestImage('tests',
                        'pytest -q --junitxml=/reports/junit.xml')
                    gate(rc, 'Pruebas automatizadas (pytest)')
                }
            }
            post { always { junit allowEmptyResults: true, testResults: 'reports/junit.xml' } }
        }

        stage('SAST - Bandit') {
            steps {
                script {
                    // Falla si hay hallazgos de severidad MEDIA o ALTA (-ll)
                    def rc = runInTestImage('sast',
                        'bandit -r app.py -f json -o /reports/bandit.json; ' +
                        'bandit -r app.py -f html -o /reports/bandit.html; ' +
                        'bandit -r app.py -ll')
                    gate(rc, 'SAST (Bandit)')
                }
            }
        }

        stage('SCA - Gestion de dependencias') {
            steps {
                script {
                    // pip-audit consulta la base de vulnerabilidades de PyPI/OSV.
                    // Las actualizaciones las propone Dependabot (.github/dependabot.yml)
                    // y este stage verifica que NO introduzcan vulnerabilidades.
                    def rc = runInTestImage('sca',
                        'pip-audit -r requirements.txt -f json -o /reports/pip-audit.json; ' +
                        'pip-audit -r requirements.txt -f markdown -o /reports/pip-audit.md; ' +
                        'pip check > /reports/pip-check.txt; ' +
                        'pip-audit -r requirements.txt --strict')
                    gate(rc, 'SCA (pip-audit)')
                }
            }
        }

        stage('Deploy Staging') {
            steps {
                sh '''
                    docker network inspect "$NET" >/dev/null 2>&1 || docker network create "$NET"
                    docker rm -f "$STAGING" >/dev/null 2>&1 || true
                    docker run -d --name "$STAGING" --network "$NET" \
                        -e SECRET_KEY="$SECRET_KEY" -e KEVIN_PASSWORD="$SCAN_PASSWORD" "$IMAGE"
                    for i in $(seq 1 30); do
                        if docker run --rm --network "$NET" curlimages/curl -fsS "http://$STAGING:5000/login" >/dev/null 2>&1; then
                            echo "Staging disponible"; exit 0; fi
                        sleep 2
                    done
                    echo "Staging no respondio"; docker logs "$STAGING"; exit 1
                '''
            }
        }

        stage('DAST - OWASP ZAP') {
            steps {
                script {
                    // Cookie de sesion para escanear tambien las paginas autenticadas
                    def cookie = sh(returnStdout: true, script: '''
                        docker run --rm --network "$NET" "$TEST_IMAGE" \
                          python /scripts/get_session.py "http://$STAGING:5000" "$SCAN_USER" "$SCAN_PASSWORD" || true
                    ''').trim()
                    def zapCmd = params.ZAP_SCAN == 'full' ? 'zap-full-scan.py -m 2 -T 15' : 'zap-baseline.py -m 2'
                    sh "docker rm -f zap-${BUILD_NUMBER} >/dev/null 2>&1 || true"
                    sh """
                        docker create --name zap-${BUILD_NUMBER} --network "\$NET" \
                          -e ZAP_AUTH_HEADER=Cookie -e ZAP_AUTH_HEADER_VALUE='${cookie}' \
                          -e ZAP_AUTH_HEADER_SITE="\$STAGING" \
                          ${ZAP_IMAGE} ${zapCmd} -t http://\$STAGING:5000 \
                          -c rules.tsv -r zap-report.html -J zap-report.json -w zap-report.md -I -z "-silent"
                        rm -rf zapwrk && mkdir -p zapwrk && cp .zap/rules.tsv zapwrk/ && chmod 777 zapwrk && chmod 666 zapwrk/rules.tsv
                        docker cp -a zapwrk/. zap-${BUILD_NUMBER}:/zap/wrk
                    """
                    def rc = sh(returnStatus: true, script: "docker start -a zap-${BUILD_NUMBER}")
                    sh "docker cp zap-${BUILD_NUMBER}:/zap/wrk/. reports/zap/ || true"
                    sh "docker rm -f zap-${BUILD_NUMBER} >/dev/null 2>&1 || true"
                    // rc 1 = alguna regla configurada como FAIL en .zap/rules.tsv
                    gate(rc, 'DAST (OWASP ZAP)')
                }
            }
            post {
                always {
                    publishHTML(target: [reportDir: 'reports/zap', reportFiles: 'zap-report.html',
                        reportName: 'OWASP ZAP', keepAll: true, alwaysLinkToLastBuild: true, allowMissing: true])
                }
            }
        }

        stage('Documentacion y Trazabilidad') {
            steps {
                sh '''
                    docker rm -f "doc-$BUILD_NUMBER" >/dev/null 2>&1 || true
                    docker create --name "doc-$BUILD_NUMBER" -w /work \
                        -e BUILD_NUMBER -e BUILD_URL -e IMAGE -e GIT_COMMIT -e BRANCH_NAME "$TEST_IMAGE" \
                        sh -c "python /scripts/generate_traceability.py /work/reports /work/reports/TRAZABILIDAD_build_${BUILD_NUMBER}.md && cd /app && python -m pydoc -w app && mv app.html /work/reports/API_app.html"
                    docker cp . "doc-$BUILD_NUMBER":/work
                    docker start -a "doc-$BUILD_NUMBER"
                    docker cp "doc-$BUILD_NUMBER":/work/reports/. reports/
                    docker rm -f "doc-$BUILD_NUMBER" >/dev/null
                '''
            }
        }

        stage('Deploy Produccion') {
            when { expression { params.DEPLOY_PROD && currentBuild.currentResult == 'SUCCESS' } }
            steps {
                sh '''
                    docker rm -f "$PROD" >/dev/null 2>&1 || true
                    docker volume create securedev-data >/dev/null
                    docker run -d --name "$PROD" --network "$NET" --restart unless-stopped \
                        -p 5000:5000 -v securedev-data:/data \
                        --read-only --tmpfs /tmp --cap-drop ALL --cap-add NET_RAW \
                        --security-opt no-new-privileges \
                        -e SECRET_KEY="$SECRET_KEY" "$IMAGE"
                    echo "$IMAGE desplegada en produccion (http://localhost:5000)" | tee reports/deploy.txt
                '''
            }
        }

        stage('Monitorizacion') {
            when { expression { params.DEPLOY_PROD && currentBuild.currentResult == 'SUCCESS' } }
            steps {
                sh '''
                    # Levanta/actualiza Prometheus + Grafana (configuracion versionada en monitoring/)
                    docker compose -p securedev-monitoring -f monitoring/docker-compose.yml up -d --build
                    sleep 20
                    docker run --rm --network "$NET" curlimages/curl -fsS "http://$PROD:5000/health"
                    docker run --rm --network "$NET" curlimages/curl -fsS \
                        "http://prometheus:9090/api/v1/query?query=up%7Bjob%3D%22securedev%22%7D" | tee reports/monitor-up.json
                    grep -q '"value":\\[[0-9.]*,"1"\\]' reports/monitor-up.json \
                        && echo "Prometheus recolecta metricas de produccion (up=1)"
                '''
            }
        }
    }

    post {
        always {
            sh 'docker rm -f "$STAGING" >/dev/null 2>&1 || true'
            archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true, fingerprint: true
            publishHTML(target: [reportDir: 'reports', reportFiles: 'bandit.html',
                reportName: 'Bandit SAST', keepAll: true, allowMissing: true])
        }
        success  { echo 'Pipeline OK: todos los controles de seguridad aprobados.' }
        unstable { echo 'Pipeline INESTABLE: hay hallazgos de seguridad (revisar reportes).' }
        failure  { echo 'Pipeline DETENIDO por un control de seguridad o error.' }
    }
}

// ---------------------------------------------------------------------------
// Ejecuta un comando en la imagen de pruebas y copia /reports al workspace.
// (docker cp evita problemas de rutas al usar el socket Docker del host)
// ---------------------------------------------------------------------------
def runInTestImage(String name, String cmd) {
    def c = "${name}-${env.BUILD_NUMBER}"
    sh "docker rm -f ${c} >/dev/null 2>&1 || true"
    def rc = sh(returnStatus: true, script: "docker run --name ${c} ${env.TEST_IMAGE} sh -c '${cmd}'")
    sh "docker cp ${c}:/reports/. reports/ || true"
    sh "docker rm -f ${c} >/dev/null 2>&1 || true"
    return rc
}

// Puerta de calidad de seguridad: FAILURE si ENFORCE_GATES, si no UNSTABLE.
def gate(int rc, String control) {
    if (rc != 0) {
        if (params.ENFORCE_GATES) {
            error("${control}: se detectaron vulnerabilidades/fallas (rc=${rc}). Pipeline detenido.")
        } else {
            unstable("${control}: hallazgos detectados (rc=${rc}). Se continua solo para documentar.")
        }
    } else {
        echo "${control}: OK"
    }
}
