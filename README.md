[DNA 4기] 안전한 아웃바운드 액세스를 위한 프록시 구성
======================
<br>
<img src="./images/dna4th.png" alt=""></img>
</br>


# 1. 이벤트 환경
```
아래는 임의의 값이다.
```
* 리전 : 버지니아 북부(`us-east-1`)
* AWS accout ID와 IAM User Groups과 Users
* VPC CIDR 블럭 : `10.0.0.0/16`
* EC2 Proxy 사설 IP 주소 : `10.0.139.76`
* NAT 게이트웨이의 탄력적 IP 주소 : `107.22.68.15`
* 키 페어 이름 : `dna-123456789012.pem`

# 2. IAM 사용자 생성
* 보안 정책을 적용하기 위한 신규 사용자 및 사용자 그룹 생성

# 3. VPC 생성

<br>
<img src="./images/3.0.png" alt=""></img>
</br>

* Name tag : `dna`
* VPC CIDR 블럭 : `10.0.0.0/16`
* 1개의 가용영역
* 1개의 퍼블릭 서브넷
* 1개의 프라이빗 서브넷
* 1개의 NAT 게이트웨어
* VPC 엔드포인트 없음
* **라우트 테이블 구성 확인**

# 4. EC2 키 페어 생성
* 키 페어 생성
```
dna-123456789012.pem
```
* 키 페어 다운로드 위치 확인

# 5. EC2 생성
* EC2 Proxy 생성
  - Name : `Proxy` 입력
  - OS Image : `Amazon Linux` 선택
  - Instance type : `t3.large` 선택
  - Key pair : `dna-123456789012.pem` 선택
  - Network setting
    + VPC : `dna-vpc` 선택
    + **Subnet : `dna-subnet-private1-us-east-1a` 선택**
  - Firewall(security groups) : `Create security group` 선택
  - Storage : `기본값`
* EC2 Windows 생성
  - Name : `Windows` 입력
  - OS Image : `Windows` 선택
  - Instance type : `m5.large` 선택
  - Key pair : `dna-123456789012.pem` 선택
  - Network setting
    + VPC : `dna-vpc` 선택
    + **Subnet : `dna-subnet-public1-us-east-1a` 선택**
    + **Auto-assign public IP : `Enable` 선택**
  - Firewall(security groups) : `Create security group` 선택
  - Storage : `기본값`
* Cloud9 생성
  ```
  Private EC2 Proxy 인스턴스를 관리하기 위한 환경으로, AWS Systems Manager로 대체할 수 있다.
  https://aws.amazon.com/ko/premiumsupport/knowledge-center/ec2-systems-manager-vpc-endpoints/
  ```
  
  - Name : `dna` 입력
  - Environment type : `direct access` 선택
  - Instance type : `m5.large` 선택
  - Platform : `Amazon Linux 2` 선택
  - Network setting
    + VPC :  `dna-vpc` 선택
    + **Subnet : `dna-subnet-public1-us-east-1a` 선택**



# 6. Cloud9 구성
* EC2 키 페어 업로드
* 키를 공개적으로 볼 수 없도록 명령어 실행
```
chmod 400 dna-123456789012.pem
```
<br>
<img src="./images/6.0.png"  alt=""></img>
</br>

# 7. EC2 Proxy 구성
* EC2 Proxy의 사설 IP 주소 확인 : `10.0.139.76`
* Cloud9에서 EC2 Proxy 인스턴스에 접속
```
ssh -i dna-123456789012.pem ec2-user@10.0.139.76
```
* Squid 설치
  + Squid 홈 디렉토리 : `/etc/squid`
```
sudo yum info squid
sudo su
yum install -y squid
squid -version

```
* 인증서 생성
```
mkdir /etc/squid/ssl
cd /etc/squid/ssl
openssl genrsa -out squid.key 4096
openssl req -new -key squid.key -out squid.csr -subj "/C=XX/ST=XX/L=squid/O=squid/CN=squid"
openssl x509 -req -days 3650 -in squid.csr -signkey squid.key -out squid.crt
cat squid.key squid.crt >> squid.pem

openssl x509 -in squid.crt -outform DER -out squid.der
openssl dhparam -outform PEM -out /etc/squid/ssl/squid_dhparam.pem 2048

chown squid:squid /etc/squid/ssl/*
chmod 400 /etc/squid/ssl/*

sudo cp /etc/squid/ssl/squid.pem /home/ec2-user/
sudo cp /etc/squid/ssl/squid.der /home/ec2-user/
sudo chmod 444 /home/ec2-user/squid.*
cd /home/ec2-user

```

* 인증서 데이터베이스 생성
```
mkdir -p /var/lib/squid
rm -rf /var/lib/squid/ssl_db
/usr/lib64/squid/ssl_crtd -c -s /var/lib/squid/ssl_db
chown -R squid:squid /var/lib/squid

```

* Allowed domains 구성
  + **변경 시 Squid를 재시작해야 한다.**
```
cat << EOF > /etc/squid/whitelist.txt
.amazon.com
.google.com
.cloudfront.net
.amazonaws.com
.awsstatic.com
.a2z.com

.awsapps.com
.okta.com
.oktacdn.com
EOF

```

* Squid 구성
```
cat << EOF > /etc/squid/squid.conf
visible_hostname squid
#cache deny all

sslproxy_cert_error allow all

#Log format and rotation
logformat referrer   %ts.%03tu %>a "%{Cookie}>h" "%>h"  %ru

access_log /var/log/squid/referer.log referrer

#logfile_rotate 10
#debug_options rotate=10

acl allowed_http_sites dstdomain "/etc/squid/whitelist.txt"
http_access allow allowed_http_sites

# Handle HTTP requests
http_access deny all

# Handle HTTPS requests
http_port 3128 tcpkeepalive=60,30,3 ssl-bump generate-host-certificates=on dynamic_cert_mem_cache_size=20MB cert=/etc/squid/ssl/squid.crt key=/etc/squid/ssl/squid.key cipher=HIGH:MEDIUM:!LOW:!RC4:!SEED:!IDEA:!3DES:!MD5:!EXP:!PSK:!DSS options=NO_TLSv1,NO_SSLv3,NO_SSLv2,SINGLE_DH_USE,SINGLE_ECDH_USE tls-dh=prime256v1:/etc/squid/ssl/squid_dhparam.pem

sslcrtd_program /usr/lib64/squid/ssl_crtd -s /var/lib/squid/ssl_db -M 20MB

acl allowed_https_sites dstdomain "/etc/squid/whitelist.txt"
acl step1 at_step SslBump1
acl step2 at_step SslBump2
acl step3 at_step SslBump3

request_header_access Cookie allow allowed_https_sites

ssl_bump peek step1 allowed_https_sites

#ssl_bump peek step1
#ssl_bump stare all
ssl_bump bump all
cache allow all

refresh_pattern ^ftp:           1440    20%     10080
refresh_pattern ^gopher:        1440    0%      1440
refresh_pattern -i (/cgi-bin/|\?) 0     0%      0
refresh_pattern .               0       20%     4320

access_log stdio:/var/log/squid/access.log
EOF

```
* Squid 구성 후 다음 명령으로 프로세스 확인
  + Squid 서비스 상태 확인 : ```sudo service squid status```
  + Squid 서비스 시작 : `sudo service squid start`
  + Squid 서비스 중지 : `sudo service squid stop`
  + Squid 서비스 재시작 : `sudo service squid restart`

<br>
<img src="./images/7.0.png"  alt=""></img>
</br>

* EC2 Proxy 인스턴스의 인바운드 트래픽 권한 부여 : https://docs.aws.amazon.com/ko_kr/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html
  + Inbound rule type : `Custom TCP`
  + Protocol : `TCP`
  + **Port range : `3128`**
  + **Source : `10.0.0.0/16`**

<br>
<img src="./images/7.s0.png"  alt=""></img>
</br>

# 8. EC2 Windows 구성
* RDP 접속
  - Windows 암호 확인
* 크롬 브라우저 다운로드
  - 좌측 하단 Windows Start > Server manager > Local Server > IE Enhanced Security Configuration > Off
  - 브라우저 다운로드
    ```
    https://www.google.com/intl/ko_kr/chrome/
    ```
  - 인터넷 접속 확인

<br>
<img src="./images/8.cr0.png"  alt=""></img>
<img src="./images/8.cr1.png"  alt=""></img>
<img src="./images/8.cr2.png"  alt=""></img>
</br>

* Windows Proxy 설정
  - EC2 Proxy 서버의 사설 IP 주소(`10.0.139.76`)와 Port(`3128`)를 적용
  - 인터넷 접속 확인

<br>
<img src="./images/8.p0.png"  alt=""></img>
<img src="./images/8.p1.png"  alt=""></img>

</br>

* Squid 인증서 파일 가져오기
  - EC2 키 페어를 EC2 Windows로 복사
    ```
    cd C:\Users\Administrator\
    ```
  - EC2 Proxy 인스턴스 SSH 접속 확인
    ```
    ssh -i dna-123456789012.pem ec2-user@10.0.139.76
    ```
  - EC2 Proxy 서버에 있는 PEM 인증서 파일을 EC2 Windows에 복사 
    ```
    scp -i dna-123456789012.pem ec2-user@10.0.139.76:/home/ec2-user/squid.pem ./
    ```
  - EC2 Proxy 서버에 있는 DER 인증서 파일을 EC2 Windows에 복사
    ```
    scp -i dna-123456789012.pem ec2-user@10.0.139.76:/home/ec2-user/squid.der ./
    ```
* DER 인증서 파일 설치
<br>
<img src="./images/8.c1.png"  alt=""></img>
<img src="./images/8.c2.png"  alt=""></img>
<img src="./images/8.c3.png"  alt=""></img>
<img src="./images/8.c4.png"  alt=""></img>
<img src="./images/8.c5.png"  alt=""></img>
<img src="./images/8.c6.png"  alt=""></img>
<img src="./images/8.c7.png"  alt=""></img>
<img src="./images/8.c8.png"  alt=""></img>
</br>

* Squid에서 허용하지 않는 사이트 차단 확인
<br>
<img src="./images/8.c9.png"  alt=""></img>
</br>

* AWS 관리 콘솔 액세스
  - 접속 도메인
    ```
    https://console.aws.amazon.com/
    ```
  - IAM 사용자 선택
    + 계정 ID(12자리) 입력
    + 사용자 이름 입력
    + 암호 입력
* 인증서 확인
<br>
<img src="./images/8.ccs1.png"  alt=""></img>
<img src="./images/8.ccs2.png"  alt=""></img>
<img src="./images/8.ccs3.png"  alt=""></img>
<img src="./images/8.ccs4.png"  alt=""></img>
<img src="./images/8.ccs5.png"  alt=""></img>
<img src="./images/8.ccs6.png"  alt=""></img>
<img src="./images/8.ccs7.png"  alt=""></img>
</br>

# 9. Source IP를 바탕으로 AWS에 대한 액세스 거부
* AWS 관리 콘솔에 접속해서 사용자 그룹에 대한 인라인 정책 적용 : <https://docs.aws.amazon.com/ko_kr/IAM/latest/UserGuide/reference_policies_examples_aws_deny-ip.html>
  - **NAT 게이트웨이의 공인 IP 확인(예: us-east-1)**
  - **NAT 게이트웨이의 탄력적 IP 주소가 `107.22.68.15`인 경우 아래와 같은 정책 준비**
  ```
  {
      "Version": "2012-10-17",
      "Statement": {
          "Effect": "Deny",
          "Action": "*",
          "Resource": "*",
          "Condition": {
              "NotIpAddress": {
                  "aws:SourceIp": [
                      "107.22.68.15"
                  ]
              },
              "Bool": {"aws:ViaAWSService": "false"}
          }
      }
  }

  ```
  - IAM 사용자 그룹 권한 변경
    + 인라인 정책 생성

<br>
<img src="./images/9.ip1.png"  alt=""></img>
<img src="./images/9.ip2.png"  alt=""></img>
<img src="./images/9.ip3.png"  alt=""></img>
<img src="./images/9.ip4.png"  alt=""></img>
<img src="./images/9.ip5.png"  alt=""></img>
<img src="./images/9.ip6.png"  alt=""></img>
<img src="./images/9.ip7.png"  alt=""></img>
</br>

* Source IP을 사용하지 않는 호스트에서 AWS 관리 콘솔 액세스 거부 확인
  + **Authentication과 Authorization의 분리**
<br>
<img src="./images/9.auth1.png"  alt=""></img>
</br>

* EC2 Windows에서 AWS 관리 콘솔 액세스
  + **소스 IP가 NAT 게이트웨이의 탄력적 IP 주소**
<br>
<img src="./images/9.auth2.png"  alt=""></img>
</br>

* (옵션) 정책 제거

# 10. AWS 관리 콘솔 액세스 로그 확인
* Cloud9에서 EC2 Proxy 서버에 접속
```
ssh -i dna-123456789012.pem ec2-user@10.0.139.76
```
* 관리자 권한으로 전환
```
sudo su
```
* 액세스 로그를 분석하기 위한 스크립트 생성
```
cat << EOF > ./dna.py
import re
import urllib.parse

with open("/var/log/squid/referer.log", "r") as f:
    while True:
        where = f.tell()
        line = f.readline().strip()
        list = line.split(' ')
        m = None

        if "%22accountId%22%3A%22" in line:
            m = re.search(r'%22accountId%22%3A%22\d{12}%22', line)
        if "Credential=AKIA" in line:
            m = re.search(r'Credential=AKIA\w{16}', line)
        
        if m is not None :
            m = urllib.parse.unquote(str(m))
            print(list[0:2], m)
EOF

```
* 스크립트 생성 후 다음 명령을 실행
 ```
 python3 ./dna.py
 ```
* EC2 Windows에서 AWS 관리 콘솔 액세스
* EC2 Proxy에서 액세스 로그 확인 : `accountId=\d{12}`

<br>
<img src="./images/10.logs.png"  alt=""></img>
</br>

* **다른 계정으로 AWS 콘솔 액세스**
  - AWS 콘솔 액세스
  - 액세스 로그 확인

# 11. AWS CLI 액세스 로그 확인
* EC2 Windows에 접속
* AWS CLI 설치 : https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html
```
msiexec.exe /i https://awscli.amazonaws.com/AWSCLIV2.msi
```
* 새로운 CMD 창에서 AWS CLI 버전 확인
```
aws --version
```
* HTTP 프록시 구성 : https://docs.aws.amazon.com/ko_kr/cli/latest/userguide/cli-configure-proxy.html
```
set HTTP_PROXY=http://10.0.139.76:3128
set HTTPS_PROXY=http://10.0.139.76:3128

```
* AWS 자격 증명 구성 : https://docs.aws.amazon.com/ko_kr/cli/latest/userguide/cli-configure-files.html#cli-configure-files-settings
```
aws configure
```
* CA 인증서 번들 지정 : https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-options.html#cli-configure-options-list
```
aws s3 ls --ca-bundle squid.pem --region us-east-1
```
<br>
<img src="./images/11.c0.png"  alt=""></img>
</br>

* Default 자격 증명으로 AWS CLI 액세스 후 로그 확인 : `Credential=AKIA\w{16}`
<br>
<img src="./images/11.c1.png"  alt=""></img>
</br>

* **다른 Profile로 AWS CLI 액세스**
  - Profile 등록
  ```
  aws configure --profile hacker
  ```
  - AWS CLI 액세스
  ```
  aws s3 ls --ca-bundle squid.pem --region us-east-1 --profile hacker
  ```
  - 액세스 로그 확인

# 12. AWS SSO 액세스 로그 확인
* 사용자 포털 URL
```
https://[자격 증명 스토어 ID 또는 alias].awsapps.com/start
```
* 액세스 로그 확인

# 13. 아웃바운드 트래픽을 위한 VPC 설계
* Proxy 선정
* 방화벽 선정
* 아웃바운드 트래픽 라우팅
  + Centralized egress to internet : https://docs.aws.amazon.com/whitepapers/latest/building-scalable-secure-multi-vpc-network-infrastructure/centralized-egress-to-internet.html




