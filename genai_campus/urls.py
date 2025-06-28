from django.urls import path, include
from django.views.generic import TemplateView
from rest_framework.routers import DefaultRouter
from accounts.views import (
    SchoolViewSet, CustomUserViewSet, UserSignupView, ParentStudentLinkViewSet,
    TeacherActionsViewSet, CustomTokenObtainPairView, FaceLoginView, UpdateFaceEncodingView, LogoutView
)

router = DefaultRouter()
router.register(r'schools', SchoolViewSet)
router.register(r'users', CustomUserViewSet)
router.register(r'parent-student-links', ParentStudentLinkViewSet)
router.register(r'teacher-actions', TeacherActionsViewSet, basename='teacher-actions')

urlpatterns = [
    path('api/', include(router.urls)),
    path('api/signup/', UserSignupView.as_view(), name='user-signup'),
    path('api/login/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/face-login/', FaceLoginView.as_view(), name='face-login'),
    path('api/update-face-encoding/', UpdateFaceEncodingView.as_view(), name='update-face-encoding'),
    path('api/logout/', LogoutView.as_view(), name='logout'),
    path('signup/', TemplateView.as_view(template_name='registration/signup.html'), name='signup'),
    path('login/', TemplateView.as_view(template_name='registration/login.html'), name='login'),
    path('face-login/', TemplateView.as_view(template_name='registration/face_login.html'), name='face-login'),
    path('update-face-encoding/', TemplateView.as_view(template_name='registration/update_face_encoding.html'), name='update-face-encoding'),
]