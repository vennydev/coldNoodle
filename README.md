# (물)냉면취급소

냉면에 진심인 사람을 위한
하찮지만 깐깐한 냉면 평가

1. 제작기간

- 2022년 5월 14일 ~

2. 사용 기술
   Backend

- Python
- Flask
- mongoDB

Frontend

- JQuery
- Javascript

deploy

- AWS EC2(Ubuntu 18.04 LTS)

3. 핵심기능

- 로그인, 회원가입
  : 아이디와 패스워드를 기입 할 때 필요한 기입조건들을 설정했습니다.

- 좋아요 / 좋아요 취소
  : 게시글에 좋아요를 누르고 취소 할 수도 있습니다.

- 내가 쓴 글
  : 내가 작성한 글을 프로필에서 조회 할 수 있습니다.

4. API

- 로그인 & 회원가입 페이지

  1. 기본 화면에 로그인 화면 보이기
  2. '회원가입하기' 버튼 클릭하면 회원가입 화면으로 바뀌기
  3. '취소' 버튼 클릭하면 로그인 화면으로 돌아오기
  4. 회원가입

  - 아이디 중복을 확인합니다
  - 아이디, 패스워드 형식을 확인합니다
  - post요청을 보내 db에 아이디와 암호화된 패스워드를 저장하고 로그인 화면으로 이동합니다

  5. 로그인

  - db에 입력된 아이디가 존재하는지 확인합니다
  - 아이디와 암호화시킨 비밀번호가 매칭되는지 확인
  - 회원일 경우 토큰을 부여하고 쿠키에 저장

  -메인페이지

  1. GET요청으로 db에 저장된 모든 포스트를 시간역순으로 보여주기
  2. 각 포스트에 좋아요/ 좋아요 취소 가능

     - 좋아요 누르면 찬 하트로 보여주기

  3. 포스팅 칸 클릭 시 모달창 생성

     - 포스팅하기 누르면 db에 저장
     - 새로고침하여 포스트 목록 다시 띄우기

5. 나중에 더하고 싶은 기능

- 네이버 플레이스 크롤링
- 필터 버튼(평점 높은 순, 평점 낮은 순)
