from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from .models import CustomUser, ParentStudentLink, School, StudentProfile, TeacherProfile, ParentProfile
from content.models import Class as ContentClass, Subject as ContentSubject
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import transaction
import face_recognition
import json
import numpy as np
import logging

logger = logging.getLogger(__name__)

class SchoolSerializer(serializers.ModelSerializer):
    """Serializer for creating and updating School instances with associated admin user."""
    admin_username = serializers.CharField(write_only=True, required=True)
    admin_email = serializers.EmailField(write_only=True, required=True)
    admin_password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})

    class Meta:
        model = School
        fields = [
            'id', 'name', 'school_id_code', 'license_number', 'official_email',
            'phone_number', 'address', 'principal_full_name', 'principal_contact_number',
            'principal_email', 'admin_user',
            'admin_username', 'admin_email', 'admin_password'
        ]
        read_only_fields = ['admin_user']
        extra_kwargs = {
            'school_id_code': {'validators': []},
            'official_email': {'validators': []},
        }

    def validate_admin_password(self, value):
        """Validates the admin password against Django's password validation rules."""
        try:
            validate_password(value)
            return value
        except DjangoValidationError as e:
            logger.error(f"Admin password validation failed: {e.messages}")
            raise serializers.ValidationError(list(e.messages))

    def create(self, validated_data):
        """Creates a new school with an admin user, ensuring atomicity."""
        admin_username = validated_data.pop('admin_username')
        admin_email = validated_data.pop('admin_email')
        admin_password = validated_data.pop('admin_password')

        try:
            if CustomUser.objects.filter(username=admin_username).exists():
                logger.error(f"Username {admin_username} already exists")
                raise serializers.ValidationError({"admin_username": "An admin user with this username already exists."})
            if CustomUser.objects.filter(email=admin_email).exists():
                logger.error(f"Email {admin_email} already exists")
                raise serializers.ValidationError({"admin_email": "An admin user with this email already exists."})

            admin_user = CustomUser.objects.create_user(
                username=admin_username,
                email=admin_email,
                password=admin_password,
                role='Admin',
                is_school_admin=True,
                is_staff=False,
                is_active=True
            )
            school = School.objects.create(admin_user=admin_user, **validated_data)
            admin_user.school = school
            admin_user.save()
            logger.info(f"School {school.name} created with admin {admin_username}")
            return school
        except Exception as e:
            logger.error(f"Failed to create school: {str(e)}")
            raise serializers.ValidationError({"error": f"School creation failed: {str(e)}"})

class StudentProfileSerializer(serializers.ModelSerializer):
    """Serializer for StudentProfile, providing read-only fields for related data."""
    enrolled_class_name = serializers.CharField(source='enrolled_class.name', read_only=True, allow_null=True)
    school_name = serializers.CharField(source='school.name', read_only=True, allow_null=True)
    profile_picture_url = serializers.SerializerMethodField()

    class Meta:
        model = StudentProfile
        fields = '__all__'
        read_only_fields = ['user', 'profile_picture_url', 'school_name', 'enrolled_class_name']
        extra_kwargs = {
            'school': {'required': False, 'allow_null': True},
            'enrolled_class': {'required': False, 'allow_null': True},
            'profile_picture': {'write_only': True, 'required': False, 'allow_null': True},
        }

    def get_profile_picture_url(self, obj):
        """Returns the absolute URL for the student's profile picture."""
        request = self.context.get('request')
        if obj.profile_picture and hasattr(obj.profile_picture, 'url'):
            return request.build_absolute_uri(obj.profile_picture.url) if request else obj.profile_picture.url
        return None

class TeacherProfileSerializer(serializers.ModelSerializer):
    """Serializer for TeacherProfile, including details of assigned classes and subjects."""
    school_name = serializers.CharField(source='school.name', read_only=True, allow_null=True)
    assigned_classes_details = serializers.SerializerMethodField()
    subject_expertise_details = serializers.SerializerMethodField()
    profile_picture_url = serializers.SerializerMethodField()

    class Meta:
        model = TeacherProfile
        fields = '__all__'
        read_only_fields = ['user', 'profile_picture_url', 'school_name', 'assigned_classes_details', 'subject_expertise_details']
        extra_kwargs = {
            'school': {'required': False, 'allow_null': True},
            'assigned_classes': {'required': False},
            'subject_expertise': {'required': False},
            'profile_picture': {'write_only': True, 'required': False, 'allow_null': True},
        }

    def get_assigned_classes_details(self, obj):
        """Returns details of assigned classes."""
        return [{'id': cls.id, 'name': cls.name} for cls in obj.assigned_classes.all()]

    def get_subject_expertise_details(self, obj):
        """Returns details of subject expertise."""
        return [{'id': sub.id, 'name': sub.name} for sub in obj.subject_expertise.all()]

    def get_profile_picture_url(self, obj):
        """Returns the absolute URL for the teacher's profile picture."""
        request = self.context.get('request')
        if obj.profile_picture and hasattr(obj.profile_picture, 'url'):
            return request.build_absolute_uri(obj.profile_picture.url) if request else obj.profile_picture.url
        return None

class ParentProfileSerializer(serializers.ModelSerializer):
    """Serializer for ParentProfile, including profile picture URL."""
    profile_picture_url = serializers.SerializerMethodField()

    class Meta:
        model = ParentProfile
        fields = '__all__'
        read_only_fields = ['user', 'profile_picture_url']
        extra_kwargs = {
            'profile_picture': {'write_only': True, 'required': False, 'allow_null': True},
        }

    def get_profile_picture_url(self, obj):
        """Returns the absolute URL for the parent's profile picture."""
        request = self.context.get('request')
        if obj.profile_picture and hasattr(obj.profile_picture, 'url'):
            return request.build_absolute_uri(obj.profile_picture.url) if request else obj.profile_picture.url
        return None

class CustomUserSerializer(serializers.ModelSerializer):
    """Serializer for CustomUser, including role-specific profiles and school details."""
    student_profile = StudentProfileSerializer(read_only=True)
    teacher_profile = TeacherProfileSerializer(read_only=True)
    parent_profile = ParentProfileSerializer(read_only=True)
    school_name = serializers.CharField(source='school.name', read_only=True, allow_null=True)
    school_id = serializers.PrimaryKeyRelatedField(queryset=School.objects.all(), source='school', write_only=True, allow_null=True, required=False)
    profile_completed = serializers.SerializerMethodField()
    administered_school = SchoolSerializer(read_only=True, allow_null=True)

    class Meta:
        model = CustomUser
        fields = [
            'id', 'username', 'email', 'role', 'password', 'is_school_admin',
            'school_id', 'school_name', 'administered_school',
            'student_profile', 'teacher_profile', 'parent_profile',
            'profile_completed',
        ]
        extra_kwargs = {
            'password': {'write_only': True, 'required': False},
        }

    def get_profile_completed(self, obj):
        """Determines if the user's role-specific profile is completed."""
        if obj.role == 'Student' and hasattr(obj, 'student_profile') and obj.student_profile:
            return obj.student_profile.profile_completed
        elif obj.role == 'Teacher' and hasattr(obj, 'teacher_profile') and obj.teacher_profile:
            return obj.teacher_profile.profile_completed
        elif obj.role == 'Parent' and hasattr(obj, 'parent_profile') and obj.parent_profile:
            return obj.parent_profile.profile_completed
        return False

    def create(self, validated_data):
        """Creates a new user with the provided data."""
        try:
            user = CustomUser.objects.create_user(**validated_data)
            logger.info(f"User {user.username} created successfully")
            return user
        except Exception as e:
            logger.error(f"User creation failed: {str(e)}")
            raise serializers.ValidationError({"error": f"User creation failed: {str(e)}"})

    def update(self, instance, validated_data):
        """Updates user details, including password and school if provided."""
        try:
            password = validated_data.pop('password', None)
            if password:
                instance.set_password(password)
            school = validated_data.pop('school', None)
            if school:
                instance.school = school
            updated_instance = super().update(instance, validated_data)
            logger.info(f"User {instance.username} updated successfully")
            return updated_instance
        except Exception as e:
            logger.error(f"User update failed for {instance.username}: {str(e)}")
            raise serializers.ValidationError({"error": f"User update failed: {str(e)}"})

class UserSignupSerializer(serializers.ModelSerializer):
    """Serializer for user registration, including face image validation."""
    face_image = serializers.ImageField(write_only=True, required=False)

    class Meta:
        model = CustomUser
        fields = ['id', 'username', 'email', 'role', 'password', 'face_image']
        extra_kwargs = {
            'password': {'write_only': True, 'required': True},
            'role': {'required': True}
        }

    def validate_role(self, value):
        """Ensures the selected role is valid and not 'Admin'."""
        valid_roles = [choice[0] for choice in CustomUser.ROLE_CHOICES if choice[0] != 'Admin']
        if value not in valid_roles:
            logger.error(f"Invalid role selected: {value}")
            raise serializers.ValidationError(f"Invalid role. Choose from {', '.join(valid_roles)}.", code='invalid_role')
        return value

    def validate_face_image(self, value):
        """Validates the face image for format, size, and face detection."""
        if not value:
            return value
        try:
            if not value.content_type.startswith('image/'):
                logger.error("Invalid image format provided")
                raise serializers.ValidationError("Invalid image format.", code='invalid_format')
            if value.size > 5 * 1024 * 1024:  # 5MB limit
                logger.error("Image size exceeds 5MB")
                raise serializers.ValidationError("Image size exceeds 5MB.", code='invalid_size')
            image = face_recognition.load_image_file(value)
            face_locations = face_recognition.face_locations(image)
            if len(face_locations) == 0:
                logger.warning("No face detected in provided image")
                raise serializers.ValidationError("No face detected. Please capture a clear image with one face.", code='no_face')
            if len(face_locations) > 1:
                logger.warning(f"Multiple faces detected: {len(face_locations)}")
                raise serializers.ValidationError("Multiple faces detected. Please capture an image with only one face.", code='multiple_faces')
            encodings = face_recognition.face_encodings(image, known_face_locations=face_locations)
            if not encodings:
                logger.warning("Face encoding failed due to unclear image")
                raise serializers.ValidationError("Face encoding failed. Please capture a clearer image.", code='unclear_image')
            return value
        except Exception as e:
            logger.error(f"Face image validation failed: {str(e)}")
            raise serializers.ValidationError(f"Face image processing failed: {str(e)}", code='processing_error')

    @transaction.atomic
    def create(self, validated_data):
        """Creates a new user with face encoding if provided, ensuring atomicity."""
        face_image = validated_data.pop('face_image', None)
        try:
            user = CustomUser.objects.create_user(
                username=validated_data['username'],
                email=validated_data['email'],
                password=validated_data['password'],
                role=validated_data['role'],
                is_active=True
            )
            if face_image:
                image = face_recognition.load_image_file(face_image)
                face_locations = face_recognition.face_locations(image)
                if len(face_locations) != 1:
                    logger.error(f"Invalid face count during creation: {len(face_locations)}")
                    user.delete()
                    raise serializers.ValidationError(
                        "Exactly one face must be detected.", code='invalid_face_count'
                    )
                encodings = face_recognition.face_encodings(image, known_face_locations=face_locations)
                if not encodings:
                    logger.error("Failed to generate face encoding during creation")
                    user.delete()
                    raise serializers.ValidationError(
                        "Failed to generate face encoding. Please capture a clearer image.", code='encoding_failed'
                    )
                user.face_encoding = json.dumps(encodings[0].tolist())
                user.save()
                logger.info(f"Face encoding saved for user {user.username}")
            
            if user.role == 'Student':
                StudentProfile.objects.create(user=user, profile_completed=False)
            elif user.role == 'Teacher':
                TeacherProfile.objects.create(user=user, profile_completed=False)
            elif user.role == 'Parent':
                ParentProfile.objects.create(user=user, profile_completed=False)
            logger.info(f"User {user.username} created successfully")
            return user
        except Exception as e:
            logger.error(f"Failed to create user {validated_data.get('username', 'unknown')}: {str(e)}")
            raise serializers.ValidationError(f"User creation failed: {str(e)}", code='creation_failed')

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """Custom serializer for JWT token generation with additional user details."""
    @classmethod
    def get_token(cls, user):
        """Adds role and is_school_admin to the JWT token payload."""
        token = super().get_token(user)
        token['role'] = user.role
        token['is_school_admin'] = user.is_school_admin
        return token

    def validate(self, attrs):
        """Validates login credentials and includes user details in response."""
        try:
            data = super().validate(attrs)
            data.update({
                'user_id': self.user.id,
                'username': self.user.username,
                'email': self.user.email,
                'role': self.user.role,
            })
            logger.info(f"Token generated for user {self.user.username}")
            return data
        except Exception as e:
            logger.error(f"Token validation failed: {str(e)}")
            raise serializers.ValidationError(f"Login failed: {str(e)}", code='login_failed')

class FaceLoginSerializer(serializers.Serializer):
    """Serializer for face-based login, validating email and face image."""
    email = serializers.EmailField(required=True)
    face_image = serializers.ImageField(required=True)

    def validate(self, data):
        """Validates email and face image, ensuring a single face match."""
        email = data.get('email')
        face_image = data.get('face_image')
        try:
            user = CustomUser.objects.get(email=email)
            if not user.face_encoding:
                logger.warning(f"No face encoding for user {email}")
                raise serializers.ValidationError(
                    {"face_image": "No face encoding stored for this user."}, code='no_encoding'
                )
            image = face_recognition.load_image_file(face_image)
            face_locations = face_recognition.face_locations(image)
            if len(face_locations) == 0:
                logger.warning(f"No face detected in login image for {email}")
                raise serializers.ValidationError(
                    {"face_image": "No face detected. Please capture a clear image with one face."}, code='no_face'
                )
            if len(face_locations) > 1:
                logger.warning(f"Multiple faces detected in login image for {email}: {len(face_locations)}")
                raise serializers.ValidationError(
                    {"face_image": "Multiple faces detected. Please capture an image with only one face."}, code='multiple_faces'
                )
            login_encoding = face_recognition.face_encodings(image, known_face_locations=face_locations)
            if not login_encoding:
                logger.warning(f"Face encoding failed for {email} due to unclear image")
                raise serializers.ValidationError(
                    {"face_image": "Face encoding failed. Please capture a clearer image."}, code='unclear_image'
                )
            stored_encoding = np.array(json.loads(user.face_encoding))
            match = face_recognition.compare_faces([stored_encoding], login_encoding[0], tolerance=0.6)
            if not match[0]:
                logger.warning(f"Face mismatch for user {email}")
                raise serializers.ValidationError(
                    {"face_image": "Face does not match stored encoding."}, code='face_mismatch'
                )
            data['user'] = user
            logger.info(f"Face validation successful for {email}")
            return data
        except CustomUser.DoesNotExist:
            logger.error(f"User with email {email} not found")
            raise serializers.ValidationError(
                {"email": "User with this email does not exist."}, code='user_not_found'
            )
        except Exception as e:
            logger.error(f"Face recognition failed for {email}: {str(e)}")
            raise serializers.ValidationError(
                {"face_image": f"Face recognition failed: {str(e)}"}, code='recognition_failed'
            )

class ParentStudentLinkSerializer(serializers.ModelSerializer):
    """Serializer for linking parents to students."""
    parent_username = serializers.CharField(source='parent.username', read_only=True)
    student_username = serializers.CharField(source='student.username', read_only=True)
    student_details = StudentProfileSerializer(source='student.student_profile', read_only=True)

    class Meta:
        model = ParentStudentLink
        fields = ['id', 'parent', 'student', 'parent_username', 'student_username', 'student_details']
        extra_kwargs = {
            'parent': {'queryset': CustomUser.objects.filter(role='Parent')},
            'student': {'queryset': CustomUser.objects.filter(role='Student')},
        }

    def validate(self, data):
        """Ensures parent and student roles are valid."""
        try:
            parent = data.get('parent')
            student = data.get('student')
            if parent and parent.role != 'Parent':
                logger.error(f"Invalid parent role for user {parent.username}")
                raise serializers.ValidationError({"parent": "Selected user is not a Parent."}, code='invalid_parent')
            if student and student.role != 'Student':
                logger.error(f"Invalid student role for user {student.username}")
                raise serializers.ValidationError({"student": "Selected user is not a Student."}, code='invalid_student')
            return data
        except Exception as e:
            logger.error(f"Parent-student link validation failed: {str(e)}")
            raise serializers.ValidationError({"error": f"Validation failed: {str(e)}"}, code='validation_failed')

class StudentProfileCompletionSerializer(serializers.ModelSerializer):
    """Serializer for completing student profile details."""
    school_id = serializers.PrimaryKeyRelatedField(queryset=School.objects.all(), source='school', write_only=True, allow_null=True, required=False)
    enrolled_class_id = serializers.PrimaryKeyRelatedField(queryset=ContentClass.objects.all(), source='enrolled_class', write_only=True, allow_null=True, required=False)
    profile_picture = serializers.ImageField(required=False, allow_null=True)

    class Meta:
        model = StudentProfile
        fields = [
            'full_name', 'school', 'school_id', 'enrolled_class', 'enrolled_class_id',
            'preferred_language', 'father_name', 'mother_name', 'place_of_birth',
            'date_of_birth', 'blood_group', 'needs_assistant_teacher', 'admission_number',
            'parent_email_for_linking', 'parent_mobile_for_linking', 'parent_occupation',
            'hobbies', 'favorite_sports', 'interested_in_gardening_farming', 'nickname',
            'profile_picture', 'profile_completed'
        ]
        read_only_fields = ['user', 'school', 'enrolled_class']

class TeacherProfileCompletionSerializer(serializers.ModelSerializer):
    """Serializer for completing teacher profile details."""
    school_id = serializers.PrimaryKeyRelatedField(queryset=School.objects.all(), source='school', write_only=True, allow_null=True, required=False)
    assigned_classes_ids = serializers.PrimaryKeyRelatedField(
        queryset=ContentClass.objects.all(), source='assigned_classes', many=True, required=False, write_only=True
    )
    subject_expertise_ids = serializers.PrimaryKeyRelatedField(
        queryset=ContentSubject.objects.all(), source='subject_expertise', many=True, required=False, write_only=True
    )
    profile_picture = serializers.ImageField(required=False, allow_null=True)

    class Meta:
        model = TeacherProfile
        fields = [
            'full_name', 'school', 'school_id', 'assigned_classes', 'assigned_classes_ids',
            'subject_expertise', 'subject_expertise_ids', 'interested_in_tuition',
            'mobile_number', 'address', 'profile_picture', 'profile_completed'
        ]
        read_only_fields = ['user', 'school', 'assigned_classes', 'subject_expertise']

class ParentProfileCompletionSerializer(serializers.ModelSerializer):
    """Serializer for completing parent profile details."""
    profile_picture = serializers.ImageField(required=False, allow_null=True)

    class Meta:
        model = ParentProfile
        fields = ['full_name', 'mobile_number', 'address', 'profile_picture', 'profile_completed']
        read_only_fields = ['user']