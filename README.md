# ACCOUNTS_API_WITH_DJANGO
장고를 이용하여 Account에 관련된 모든 API를 구현하는 서버코드 입니다.
## 프로젝트 소개
이 프로젝트는 모든 서비스에서 재사용 가능한 Account API를 만들기 위해서 
모든 코드를 커스텀에 용이하게 구현하는 것을 목표로 합니다. 

## 참여 인원
<table>
  <tbody>
    <tr>
      <td><a href="https://github.com/hwangtate"><img src="https://avatars.githubusercontent.com/u/139641065?s=64&v=4" width="100px;" alt=""/><br /><sub><b style="text-align: center">BE 4기 황태영 </b></sub></a><br /></td>
    </tr>
  </tbody>
</table>

## 사용 스택
<div>
    <img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="">
    <img src="https://img.shields.io/badge/Django-092E20?style=for-the-badge&logo=django&logoColor=white" alt="">
    <img src="https://img.shields.io/badge/GitHub-181717?style=for-the-badge&logo=github&logoColor=white" alt="">
    <img src="https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=Docker&logoColor=white" alt="">
    <img src="https://img.shields.io/badge/MySQL-4479A1?style=for-the-badge&logo=MySQL&logoColor=white" alt="">
    <img src="https://img.shields.io/badge/Redis-FF4438?style=for-the-badge&logo=redis&logoColor=white" alt="">
</div> 


## 프로젝트 구조

```
📦 Project
├─ .dockerignore
├─ .gitignore
├─ .env
├─ .gitmessage.txt
├─ compose.yaml
├─ Dockerfile
├─ poetry.lock
├─ poetry.toml
├─ README.md
├─ manage.py
├─ accounts
│  ├─ admin.py
│  ├─ apps.py
│  ├─ manager.py
│  ├─ models.py
│  ├─ permissions.py
│  ├─ serializers.py
│  ├─ tests.py
│  ├─ urls.py
│  └─ views.py
├─ coreapp
│  ├─ settings
│  │  ├─ base.py
│  │  ├─ development.py
│  │  └─ production.py
│  ├─ asgi.py
│  ├─ middleware.py
│  ├─ urls.py
│  └─ wsgi.py
└─ templates
```
## Accounts App 기능구현 현황
- [X] User List API
- [X] User Detail API
- [X] Profile API
- [X] Register API
- [X] Login API
- [X] Logout API
- [ ] Email Auth API (register)
- [ ] Change Email API
- [ ] Find Password API
- [ ] Reset Password API
- [ ] Social Register
- [ ] Social Login


