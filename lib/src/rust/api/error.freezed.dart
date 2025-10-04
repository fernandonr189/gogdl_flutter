// GENERATED CODE - DO NOT MODIFY BY HAND
// coverage:ignore-file
// ignore_for_file: type=lint
// ignore_for_file: unused_element, deprecated_member_use, deprecated_member_use_from_same_package, use_function_type_syntax_for_parameters, unnecessary_const, avoid_init_to_null, invalid_override_different_default_values_named, prefer_expression_function_bodies, annotate_overrides, invalid_annotation_target, unnecessary_question_mark

part of 'error.dart';

// **************************************************************************
// FreezedGenerator
// **************************************************************************

// dart format off
T _$identity<T>(T value) => value;
/// @nodoc
mixin _$AuthError {

 String get field0;
/// Create a copy of AuthError
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$AuthErrorCopyWith<AuthError> get copyWith => _$AuthErrorCopyWithImpl<AuthError>(this as AuthError, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is AuthError&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'AuthError(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $AuthErrorCopyWith<$Res>  {
  factory $AuthErrorCopyWith(AuthError value, $Res Function(AuthError) _then) = _$AuthErrorCopyWithImpl;
@useResult
$Res call({
 String field0
});




}
/// @nodoc
class _$AuthErrorCopyWithImpl<$Res>
    implements $AuthErrorCopyWith<$Res> {
  _$AuthErrorCopyWithImpl(this._self, this._then);

  final AuthError _self;
  final $Res Function(AuthError) _then;

/// Create a copy of AuthError
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') @override $Res call({Object? field0 = null,}) {
  return _then(_self.copyWith(
field0: null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as String,
  ));
}

}


/// Adds pattern-matching-related methods to [AuthError].
extension AuthErrorPatterns on AuthError {
/// A variant of `map` that fallback to returning `orElse`.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case _:
///     return orElse();
/// }
/// ```

@optionalTypeArgs TResult maybeMap<TResult extends Object?>({TResult Function( AuthError_Network value)?  network,TResult Function( AuthError_Io value)?  io,TResult Function( AuthError_UrlError value)?  urlError,TResult Function( AuthError_InvalidResponse value)?  invalidResponse,TResult Function( AuthError_Auth value)?  auth,required TResult orElse(),}){
final _that = this;
switch (_that) {
case AuthError_Network() when network != null:
return network(_that);case AuthError_Io() when io != null:
return io(_that);case AuthError_UrlError() when urlError != null:
return urlError(_that);case AuthError_InvalidResponse() when invalidResponse != null:
return invalidResponse(_that);case AuthError_Auth() when auth != null:
return auth(_that);case _:
  return orElse();

}
}
/// A `switch`-like method, using callbacks.
///
/// Callbacks receives the raw object, upcasted.
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case final Subclass2 value:
///     return ...;
/// }
/// ```

@optionalTypeArgs TResult map<TResult extends Object?>({required TResult Function( AuthError_Network value)  network,required TResult Function( AuthError_Io value)  io,required TResult Function( AuthError_UrlError value)  urlError,required TResult Function( AuthError_InvalidResponse value)  invalidResponse,required TResult Function( AuthError_Auth value)  auth,}){
final _that = this;
switch (_that) {
case AuthError_Network():
return network(_that);case AuthError_Io():
return io(_that);case AuthError_UrlError():
return urlError(_that);case AuthError_InvalidResponse():
return invalidResponse(_that);case AuthError_Auth():
return auth(_that);}
}
/// A variant of `map` that fallback to returning `null`.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case _:
///     return null;
/// }
/// ```

@optionalTypeArgs TResult? mapOrNull<TResult extends Object?>({TResult? Function( AuthError_Network value)?  network,TResult? Function( AuthError_Io value)?  io,TResult? Function( AuthError_UrlError value)?  urlError,TResult? Function( AuthError_InvalidResponse value)?  invalidResponse,TResult? Function( AuthError_Auth value)?  auth,}){
final _that = this;
switch (_that) {
case AuthError_Network() when network != null:
return network(_that);case AuthError_Io() when io != null:
return io(_that);case AuthError_UrlError() when urlError != null:
return urlError(_that);case AuthError_InvalidResponse() when invalidResponse != null:
return invalidResponse(_that);case AuthError_Auth() when auth != null:
return auth(_that);case _:
  return null;

}
}
/// A variant of `when` that fallback to an `orElse` callback.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case _:
///     return orElse();
/// }
/// ```

@optionalTypeArgs TResult maybeWhen<TResult extends Object?>({TResult Function( String field0)?  network,TResult Function( String field0)?  io,TResult Function( String field0)?  urlError,TResult Function( String field0)?  invalidResponse,TResult Function( String field0)?  auth,required TResult orElse(),}) {final _that = this;
switch (_that) {
case AuthError_Network() when network != null:
return network(_that.field0);case AuthError_Io() when io != null:
return io(_that.field0);case AuthError_UrlError() when urlError != null:
return urlError(_that.field0);case AuthError_InvalidResponse() when invalidResponse != null:
return invalidResponse(_that.field0);case AuthError_Auth() when auth != null:
return auth(_that.field0);case _:
  return orElse();

}
}
/// A `switch`-like method, using callbacks.
///
/// As opposed to `map`, this offers destructuring.
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case Subclass2(:final field2):
///     return ...;
/// }
/// ```

@optionalTypeArgs TResult when<TResult extends Object?>({required TResult Function( String field0)  network,required TResult Function( String field0)  io,required TResult Function( String field0)  urlError,required TResult Function( String field0)  invalidResponse,required TResult Function( String field0)  auth,}) {final _that = this;
switch (_that) {
case AuthError_Network():
return network(_that.field0);case AuthError_Io():
return io(_that.field0);case AuthError_UrlError():
return urlError(_that.field0);case AuthError_InvalidResponse():
return invalidResponse(_that.field0);case AuthError_Auth():
return auth(_that.field0);}
}
/// A variant of `when` that fallback to returning `null`
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case _:
///     return null;
/// }
/// ```

@optionalTypeArgs TResult? whenOrNull<TResult extends Object?>({TResult? Function( String field0)?  network,TResult? Function( String field0)?  io,TResult? Function( String field0)?  urlError,TResult? Function( String field0)?  invalidResponse,TResult? Function( String field0)?  auth,}) {final _that = this;
switch (_that) {
case AuthError_Network() when network != null:
return network(_that.field0);case AuthError_Io() when io != null:
return io(_that.field0);case AuthError_UrlError() when urlError != null:
return urlError(_that.field0);case AuthError_InvalidResponse() when invalidResponse != null:
return invalidResponse(_that.field0);case AuthError_Auth() when auth != null:
return auth(_that.field0);case _:
  return null;

}
}

}

/// @nodoc


class AuthError_Network extends AuthError {
  const AuthError_Network(this.field0): super._();
  

@override final  String field0;

/// Create a copy of AuthError
/// with the given fields replaced by the non-null parameter values.
@override @JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$AuthError_NetworkCopyWith<AuthError_Network> get copyWith => _$AuthError_NetworkCopyWithImpl<AuthError_Network>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is AuthError_Network&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'AuthError.network(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $AuthError_NetworkCopyWith<$Res> implements $AuthErrorCopyWith<$Res> {
  factory $AuthError_NetworkCopyWith(AuthError_Network value, $Res Function(AuthError_Network) _then) = _$AuthError_NetworkCopyWithImpl;
@override @useResult
$Res call({
 String field0
});




}
/// @nodoc
class _$AuthError_NetworkCopyWithImpl<$Res>
    implements $AuthError_NetworkCopyWith<$Res> {
  _$AuthError_NetworkCopyWithImpl(this._self, this._then);

  final AuthError_Network _self;
  final $Res Function(AuthError_Network) _then;

/// Create a copy of AuthError
/// with the given fields replaced by the non-null parameter values.
@override @pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(AuthError_Network(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class AuthError_Io extends AuthError {
  const AuthError_Io(this.field0): super._();
  

@override final  String field0;

/// Create a copy of AuthError
/// with the given fields replaced by the non-null parameter values.
@override @JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$AuthError_IoCopyWith<AuthError_Io> get copyWith => _$AuthError_IoCopyWithImpl<AuthError_Io>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is AuthError_Io&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'AuthError.io(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $AuthError_IoCopyWith<$Res> implements $AuthErrorCopyWith<$Res> {
  factory $AuthError_IoCopyWith(AuthError_Io value, $Res Function(AuthError_Io) _then) = _$AuthError_IoCopyWithImpl;
@override @useResult
$Res call({
 String field0
});




}
/// @nodoc
class _$AuthError_IoCopyWithImpl<$Res>
    implements $AuthError_IoCopyWith<$Res> {
  _$AuthError_IoCopyWithImpl(this._self, this._then);

  final AuthError_Io _self;
  final $Res Function(AuthError_Io) _then;

/// Create a copy of AuthError
/// with the given fields replaced by the non-null parameter values.
@override @pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(AuthError_Io(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class AuthError_UrlError extends AuthError {
  const AuthError_UrlError(this.field0): super._();
  

@override final  String field0;

/// Create a copy of AuthError
/// with the given fields replaced by the non-null parameter values.
@override @JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$AuthError_UrlErrorCopyWith<AuthError_UrlError> get copyWith => _$AuthError_UrlErrorCopyWithImpl<AuthError_UrlError>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is AuthError_UrlError&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'AuthError.urlError(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $AuthError_UrlErrorCopyWith<$Res> implements $AuthErrorCopyWith<$Res> {
  factory $AuthError_UrlErrorCopyWith(AuthError_UrlError value, $Res Function(AuthError_UrlError) _then) = _$AuthError_UrlErrorCopyWithImpl;
@override @useResult
$Res call({
 String field0
});




}
/// @nodoc
class _$AuthError_UrlErrorCopyWithImpl<$Res>
    implements $AuthError_UrlErrorCopyWith<$Res> {
  _$AuthError_UrlErrorCopyWithImpl(this._self, this._then);

  final AuthError_UrlError _self;
  final $Res Function(AuthError_UrlError) _then;

/// Create a copy of AuthError
/// with the given fields replaced by the non-null parameter values.
@override @pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(AuthError_UrlError(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class AuthError_InvalidResponse extends AuthError {
  const AuthError_InvalidResponse(this.field0): super._();
  

@override final  String field0;

/// Create a copy of AuthError
/// with the given fields replaced by the non-null parameter values.
@override @JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$AuthError_InvalidResponseCopyWith<AuthError_InvalidResponse> get copyWith => _$AuthError_InvalidResponseCopyWithImpl<AuthError_InvalidResponse>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is AuthError_InvalidResponse&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'AuthError.invalidResponse(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $AuthError_InvalidResponseCopyWith<$Res> implements $AuthErrorCopyWith<$Res> {
  factory $AuthError_InvalidResponseCopyWith(AuthError_InvalidResponse value, $Res Function(AuthError_InvalidResponse) _then) = _$AuthError_InvalidResponseCopyWithImpl;
@override @useResult
$Res call({
 String field0
});




}
/// @nodoc
class _$AuthError_InvalidResponseCopyWithImpl<$Res>
    implements $AuthError_InvalidResponseCopyWith<$Res> {
  _$AuthError_InvalidResponseCopyWithImpl(this._self, this._then);

  final AuthError_InvalidResponse _self;
  final $Res Function(AuthError_InvalidResponse) _then;

/// Create a copy of AuthError
/// with the given fields replaced by the non-null parameter values.
@override @pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(AuthError_InvalidResponse(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class AuthError_Auth extends AuthError {
  const AuthError_Auth(this.field0): super._();
  

@override final  String field0;

/// Create a copy of AuthError
/// with the given fields replaced by the non-null parameter values.
@override @JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$AuthError_AuthCopyWith<AuthError_Auth> get copyWith => _$AuthError_AuthCopyWithImpl<AuthError_Auth>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is AuthError_Auth&&(identical(other.field0, field0) || other.field0 == field0));
}


@override
int get hashCode => Object.hash(runtimeType,field0);

@override
String toString() {
  return 'AuthError.auth(field0: $field0)';
}


}

/// @nodoc
abstract mixin class $AuthError_AuthCopyWith<$Res> implements $AuthErrorCopyWith<$Res> {
  factory $AuthError_AuthCopyWith(AuthError_Auth value, $Res Function(AuthError_Auth) _then) = _$AuthError_AuthCopyWithImpl;
@override @useResult
$Res call({
 String field0
});




}
/// @nodoc
class _$AuthError_AuthCopyWithImpl<$Res>
    implements $AuthError_AuthCopyWith<$Res> {
  _$AuthError_AuthCopyWithImpl(this._self, this._then);

  final AuthError_Auth _self;
  final $Res Function(AuthError_Auth) _then;

/// Create a copy of AuthError
/// with the given fields replaced by the non-null parameter values.
@override @pragma('vm:prefer-inline') $Res call({Object? field0 = null,}) {
  return _then(AuthError_Auth(
null == field0 ? _self.field0 : field0 // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

// dart format on
