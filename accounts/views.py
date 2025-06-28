from rest_framework import viewsets, status, generics, permissions, serializers
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny, IsAdminUser
from rest_framework.exceptions import PermissionDenied
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken
import django_filters.rest_framework # type: ignore
from .models import CustomUser, ParentStudentLink, School, StudentProfile, TeacherProfile, ParentProfile
from content.models import Class as ContentClass
from .serializers import (
    CustomUserSerializer, UserSignupSerializer, ParentStudentLinkSerializer,
    SchoolSerializer, StudentProfileSerializer, TeacherProfileSerializer, ParentProfileSerializer,
    StudentProfileCompletionSerializer, TeacherProfileCompletionSerializer, ParentProfileCompletionSerializer,
    CustomTokenObtainPairSerializer, FaceLoginSerializer
)
from .permissions import IsParent, IsTeacher, IsTeacherOrReadOnly, IsAdminOfThisSchoolOrPlatformStaff
import logging

logger = logging.getLogger(__name__)

class SchoolViewSet(viewsets.ModelViewSet):
    queryset = School.objects.all()
    serializer_class = SchoolSerializer
    filter_backends = [django_filters.rest_framework.DjangoFilterBackend]
    filterset_fields = ['name', 'school_id_code']

    def get_permissions(self):
        if self.action == 'create':
            self.permission_classes = [permissions.AllowAny]
        elif self.action in ['update', 'partial_update']:
            self.permission_classes = [permissions.IsAuthenticated, IsAdminOfThisSchoolOrPlatformStaff]
        elif self.action == 'destroy':
            self.permission_classes = [permissions.IsAdminUser]
        else:
            self.permission_classes = [permissions.IsAuthenticatedOrReadOnly]
        return super().get_permissions()

class CustomUserViewSet(viewsets.ModelViewSet):
    queryset = CustomUser.objects.all().select_related('student_profile', 'teacher_profile', 'parent_profile', 'school', 'administered_school')
    serializer_class = CustomUserSerializer
    filter_backends = [django_filters.rest_framework.DjangoFilterBackend]
    filterset_fields = ['role', 'username', 'email', 'school']

    def get_serializer_context(self):
        return {'request': self.request}

    def get_permissions(self):
        if self.action == 'me':
            self.permission_classes = [IsAuthenticated]
        elif self.action == 'update_profile':
            self.permission_classes = [IsAuthenticated]
        elif self.action == 'create':
            self.permission_classes = [IsAdminUser]
        elif self.action in ['list', 'retrieve']:
            self.permission_classes = [permissions.IsAuthenticatedOrReadOnly]
        else:
            self.permission_classes = [IsAdminUser]
        return super().get_permissions()

    @action(detail=False, methods=['get'], url_path='me')
    def me(self, request):
        serializer = self.get_serializer(request.user, context=self.get_serializer_context())
        return Response(serializer.data)

    @action(detail=True, methods=['patch'], url_path='profile')
    def update_profile(self, request, pk=None):
        user = self.get_object()
        if user != request.user and not request.user.is_staff:
            logger.warning(f"User {request.user.username} attempted to update profile of user {user.username}")
            raise PermissionDenied("You can only update your own profile or you lack staff permissions.")

        profile_data_from_request = request.data.copy()
        custom_user_update_data = {}
        if 'username' in profile_data_from_request and profile_data_from_request['username'] and profile_data_from_request['username'] != user.username:
            username_val = profile_data_from_request.pop('username')
            custom_user_update_data['username'] = (username_val[0] if isinstance(username_val, list) else username_val)
        if 'email' in profile_data_from_request and profile_data_from_request['email'] != user.email:
            email_val = profile_data_from_request.pop('email')
            custom_user_update_data['email'] = (email_val[0] if isinstance(username_val, list) else email_val) or ""
        if 'password' in profile_data_from_request and profile_data_from_request['password']:
            password_val = profile_data_from_request.pop('password')
            custom_user_update_data['password'] = (password_val[0] if isinstance(password_val, list) else password_val)

        if custom_user_update_data:
            user_serializer = CustomUserSerializer(user, data=custom_user_update_data, partial=True, context=self.get_serializer_context())
            if user_serializer.is_valid():
                user_serializer.save()
            else:
                logger.error(f"User profile update failed for {user.username}: {user_serializer.errors}")
                return Response(user_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        profile_serializer_class = None
        profile_instance = None
        profile_specific_data = profile_data_from_request
        if 'profile_picture' in request.FILES:
            profile_specific_data['profile_picture'] = request.FILES['profile_picture']

        if user.role == 'Student':
            profile_serializer_class = StudentProfileCompletionSerializer
            profile_instance, _ = StudentProfile.objects.get_or_create(user=user)
            if 'school_id' in profile_specific_data and profile_specific_data['school_id']:
                try:
                    user.school = School.objects.get(pk=profile_specific_data['school_id'])
                    user.save(update_fields=['school'])
                except School.DoesNotExist:
                    pass
        elif user.role == 'Teacher':
            profile_serializer_class = TeacherProfileCompletionSerializer
            profile_instance, _ = TeacherProfile.objects.get_or_create(user=user)
            if 'school_id' in profile_specific_data and profile_specific_data['school_id']:
                try:
                    user.school = School.objects.get(pk=profile_specific_data['school_id'])
                    user.save(update_fields=['school'])
                except School.DoesNotExist:
                    pass
        elif user.role == 'Parent':
            profile_serializer_class = ParentProfileCompletionSerializer
            profile_instance, _ = ParentProfile.objects.get_or_create(user=user)

        if profile_serializer_class and profile_instance:
            if request.path.endswith('/complete-profile/'):
                profile_specific_data['profile_completed'] = True
            profile_serializer = profile_serializer_class(profile_instance, data=profile_specific_data, partial=True, context=self.get_serializer_context())
            if profile_serializer.is_valid():
                profile_serializer.save()
            else:
                logger.error(f"Profile completion failed for {user.username}: {profile_serializer.errors}")
                return Response(profile_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        user.refresh_from_db()
        final_user_serializer = CustomUserSerializer(user, context=self.get_serializer_context())
        return Response(final_user_serializer.data, status=status.HTTP_200_OK)

class UserSignupView(generics.CreateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = UserSignupSerializer
    permission_classes = [AllowAny]

    def perform_create(self, serializer):
        try:
            serializer.save()
            logger.info(f"User {serializer.validated_data['username']} signed up successfully")
        except Exception as e:
            logger.error(f"Signup failed: {str(e)}")
            raise

class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer

class FaceLoginView(generics.GenericAPIView):
    serializer_class = FaceLoginSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        try:
            refresh = RefreshToken.for_user(user)
            logger.info(f"Face login successful for {user.username}")
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'user_id': user.id,
                'username': user.username,
                'email': user.email,
                'role': user.role,
            }, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Face login token generation failed for {user.username}: {str(e)}")
            return Response({"error": "Token generation failed"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class UpdateFaceEncodingView(generics.GenericAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = FaceLoginSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = request.user
        face_image = serializer.validated_data['face_image']
        try:
            image = face_recognition.load_image_file(face_image)
            encodings = face_recognition.face_encodings(image)
            if not encodings:
                logger.warning(f"No face detected in update image for {user.username}")
                return Response({"error": "No face detected in the provided image."}, status=status.HTTP_400_BAD_REQUEST)
            user.face_encoding = json.dumps(encodings[0].tolist())
            user.save()
            logger.info(f"Face encoding updated for {user.username}")
            return Response({"message": "Face encoding updated successfully."}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Face encoding update failed for {user.username}: {str(e)}")
            return Response({"error": f"Face encoding update failed: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class LogoutView(generics.GenericAPIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        try:
            refresh_token = request.data.get("refresh")
            if not refresh_token:
                logger.warning(f"Logout attempted without refresh token by {request.user.username}")
                return Response({"error": "Refresh token required"}, status=status.HTTP_400_BAD_REQUEST)
            token = RefreshToken(refresh_token)
            token.blacklist()
            logger.info(f"User {request.user.username} logged out successfully")
            return Response({"message": "Successfully logged out"}, status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            logger.error(f"Logout failed for {request.user.username}: {str(e)}")
            return Response({"error": f"Logout failed: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)

class ParentStudentLinkViewSet(viewsets.ModelViewSet):
    queryset = ParentStudentLink.objects.all()
    serializer_class = ParentStudentLinkSerializer
    permission_classes = [IsAuthenticated]

    def get_serializer_context(self):
        return {'request': self.request}

    def get_queryset(self):
        user = self.request.user
        if user.is_staff or user.role == 'Admin':
            return ParentStudentLink.objects.all()
        if user.role == 'Parent':
            return ParentStudentLink.objects.filter(parent=user)
        if user.is_school_admin and user.school:
            students_in_school = CustomUser.objects.filter(school=user.school, role='Student')
            return ParentStudentLink.objects.filter(student__in=students_in_school)
        return ParentStudentLink.objects.none()

    def perform_create(self, serializer):
        user = self.request.user
        parent_from_data = serializer.validated_data.get('parent')
        student_from_data = serializer.validated_data.get('student')
        if user.role == 'Parent':
            if parent_from_data != user:
                logger.warning(f"Parent {user.username} attempted to link student to another parent")
                raise PermissionDenied("Parents can only link students to their own account.")
            serializer.save(parent=user)
        elif user.is_staff or user.role == 'Admin':
            if not parent_from_data or not student_from_data:
                raise serializers.ValidationError({"detail": "Parent and Student IDs must be provided by admin."})
            if user.is_school_admin and user.school and student_from_data.school != user.school:
                logger.warning(f"School admin {user.username} attempted to link student outside their school")
                raise PermissionDenied("School admins can only link students within their own school.")
            serializer.save()
        else:
            logger.warning(f"User {user.username} attempted to create parent-student link without permission")
            raise PermissionDenied("You do not have permission to create this link.")

    @action(detail=False, methods=['post'], permission_classes=[IsAuthenticated, IsParent], url_path='link-child-by-admission')
    def link_child_by_admission(self, request):
        parent_user = request.user
        student_admission_number = request.data.get('admission_number')
        student_school_id_code = request.data.get('school_id_code')

        if not student_admission_number or not student_school_id_code:
            logger.warning(f"Parent {parent_user.username} attempted link without admission number or school ID")
            return Response({"error": "Student admission number and school ID code are required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            student_profile = StudentProfile.objects.get(
                admission_number=student_admission_number,
                school__school_id_code=student_school_id_code
            )
            if student_profile.parent_email_for_linking != parent_user.email:
                logger.warning(f"Parent email mismatch for {parent_user.username}")
                return Response({"error": "Parent email on student record does not match your email."}, status=status.HTTP_403_FORBIDDEN)
            student_user = student_profile.user
        except StudentProfile.DoesNotExist:
            logger.error(f"Student not found for admission number {student_admission_number}")
            return Response({"error": "Student not found with provided details."}, status=status.HTTP_404_NOT_FOUND)

        link, created = ParentStudentLink.objects.get_or_create(parent=parent_user, student=student_user)
        serialized_student_profile = StudentProfileSerializer(student_profile, context={'request': request}).data
        response_data = {
            "link_id": link.id,
            "message": "Link established successfully." if created else "Link already exists.",
            "student_details": serialized_student_profile
        }
        status_code = status.HTTP_201_CREATED if created else status.HTTP_200_OK
        logger.info(f"Parent {parent_user.username} linked student {student_user.username}")
        return Response(response_data, status=status_code)

class TeacherActionsViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated, IsTeacher | IsAdminUser]

    @action(detail=False, methods=['get'])
    def my_classes(self, request):
        teacher_profile = getattr(request.user, 'teacher_profile', None)
        if teacher_profile:
            classes = teacher_profile.assigned_classes.all()
            return Response([{'id': c.id, 'name': c.name} for c in classes])
        logger.warning(f"Teacher {request.user.username} has no teacher profile")
        return Response([])