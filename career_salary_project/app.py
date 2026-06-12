# app.py — 프로젝트 진입점
import streamlit as st

# 1. 페이지 기본 설정
st.set_page_config(
    page_title="개발자 연봉 예측 및 기술스택 추천 서비스",
    page_icon="💻",
    layout="wide",
    initial_sidebar_state="expanded",
)

# 2. 페이지 정의 (폴더명을 views로 변경하여 Streamlit 자동 탐색 충돌 방지)
eda = st.Page("views/1_EDA.py", title="데이터 프로파일링 (EDA)", icon="📊", default=True)
viz = st.Page("views/2_시각화.py", title="트렌드 시각화 분석", icon="📈")
service = st.Page("views/3_모델_서비스.py", title="연봉 예측 & 맞춤 추천", icon="🤖")

# 교수님 가이드라인 구조 반영
pg = st.navigation({
    "프로젝트": [eda, viz, service],
})

# 3. 사이드바 공통 영역 설정
st.sidebar.markdown("### 💻 개발자 맞춤 추천 서비스")
st.sidebar.caption("빅데이터분석프로젝트 기말 과제")
st.sidebar.markdown("---")
st.sidebar.markdown("""
**• 이름:** 조정인  
**• 학번:** 20242522 
**• 소속:** 인공지능소프트웨어공학과  
""")
st.sidebar.markdown("---")
st.sidebar.caption("데이터 출처: Stack Overflow Survey 2025")

# 멀티페이지 구동
pg.run()