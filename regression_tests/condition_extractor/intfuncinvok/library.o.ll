; ModuleID = 'library.o.bc'
source_filename = "llvm-link"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

%struct.my_struct = type { i32, i32, i8, double }

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @set_default(%struct.my_struct* %0) #0 !dbg !22 {
  %2 = alloca %struct.my_struct*, align 8
  store %struct.my_struct* %0, %struct.my_struct** %2, align 8
  call void @llvm.dbg.declare(metadata %struct.my_struct** %2, metadata !25, metadata !DIExpression()), !dbg !26
  %3 = load %struct.my_struct*, %struct.my_struct** %2, align 8, !dbg !27
  %4 = getelementptr inbounds %struct.my_struct, %struct.my_struct* %3, i32 0, i32 0, !dbg !28
  store i32 4, i32* %4, align 8, !dbg !29
  %5 = load %struct.my_struct*, %struct.my_struct** %2, align 8, !dbg !30
  %6 = getelementptr inbounds %struct.my_struct, %struct.my_struct* %5, i32 0, i32 1, !dbg !31
  store i32 8, i32* %6, align 4, !dbg !32
  %7 = load %struct.my_struct*, %struct.my_struct** %2, align 8, !dbg !33
  %8 = getelementptr inbounds %struct.my_struct, %struct.my_struct* %7, i32 0, i32 2, !dbg !34
  store i8 88, i8* %8, align 8, !dbg !35
  %9 = load %struct.my_struct*, %struct.my_struct** %2, align 8, !dbg !36
  %10 = getelementptr inbounds %struct.my_struct, %struct.my_struct* %9, i32 0, i32 3, !dbg !37
  store double 1.230000e+01, double* %10, align 8, !dbg !38
  ret void, !dbg !39
}

; Function Attrs: nofree nosync nounwind readnone speculatable willreturn
declare void @llvm.dbg.declare(metadata, metadata, metadata) #1

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @swap_fields(i32* %0, i32* %1) #0 !dbg !40 {
  %3 = alloca i32*, align 8
  %4 = alloca i32*, align 8
  %5 = alloca i32, align 4
  store i32* %0, i32** %3, align 8
  call void @llvm.dbg.declare(metadata i32** %3, metadata !44, metadata !DIExpression()), !dbg !45
  store i32* %1, i32** %4, align 8
  call void @llvm.dbg.declare(metadata i32** %4, metadata !46, metadata !DIExpression()), !dbg !47
  call void @llvm.dbg.declare(metadata i32* %5, metadata !48, metadata !DIExpression()), !dbg !49
  %6 = load i32*, i32** %3, align 8, !dbg !50
  %7 = load i32, i32* %6, align 4, !dbg !51
  store i32 %7, i32* %5, align 4, !dbg !49
  %8 = load i32*, i32** %4, align 8, !dbg !52
  %9 = load i32, i32* %8, align 4, !dbg !53
  %10 = load i32*, i32** %3, align 8, !dbg !54
  store i32 %9, i32* %10, align 4, !dbg !55
  %11 = load i32, i32* %5, align 4, !dbg !56
  %12 = load i32*, i32** %4, align 8, !dbg !57
  store i32 %11, i32* %12, align 4, !dbg !58
  ret void, !dbg !59
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local %struct.my_struct* @api1(i32 %0, i32 %1, i8 signext %2, double %3, i16 signext %4) #0 !dbg !60 {
  %6 = alloca i32, align 4
  %7 = alloca i32, align 4
  %8 = alloca i8, align 1
  %9 = alloca double, align 8
  %10 = alloca i16, align 2
  %11 = alloca %struct.my_struct*, align 8
  store i32 %0, i32* %6, align 4
  call void @llvm.dbg.declare(metadata i32* %6, metadata !64, metadata !DIExpression()), !dbg !65
  store i32 %1, i32* %7, align 4
  call void @llvm.dbg.declare(metadata i32* %7, metadata !66, metadata !DIExpression()), !dbg !67
  store i8 %2, i8* %8, align 1
  call void @llvm.dbg.declare(metadata i8* %8, metadata !68, metadata !DIExpression()), !dbg !69
  store double %3, double* %9, align 8
  call void @llvm.dbg.declare(metadata double* %9, metadata !70, metadata !DIExpression()), !dbg !71
  store i16 %4, i16* %10, align 2
  call void @llvm.dbg.declare(metadata i16* %10, metadata !72, metadata !DIExpression()), !dbg !73
  call void @llvm.dbg.declare(metadata %struct.my_struct** %11, metadata !74, metadata !DIExpression()), !dbg !75
  %12 = call noalias align 16 i8* @malloc(i64 24) #3, !dbg !76
  %13 = bitcast i8* %12 to %struct.my_struct*, !dbg !77
  store %struct.my_struct* %13, %struct.my_struct** %11, align 8, !dbg !75
  %14 = load i16, i16* %10, align 2, !dbg !78
  %15 = icmp ne i16 %14, 0, !dbg !78
  br i1 %15, label %16, label %18, !dbg !80

16:                                               ; preds = %5
  %17 = load %struct.my_struct*, %struct.my_struct** %11, align 8, !dbg !81
  call void @set_default(%struct.my_struct* %17), !dbg !83
  br label %18, !dbg !84

18:                                               ; preds = %16, %5
  %19 = load %struct.my_struct*, %struct.my_struct** %11, align 8, !dbg !85
  ret %struct.my_struct* %19, !dbg !86
}

; Function Attrs: nounwind
declare dso_local noalias align 16 i8* @malloc(i64) #2

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @api2(%struct.my_struct* %0) #0 !dbg !87 {
  %2 = alloca %struct.my_struct*, align 8
  store %struct.my_struct* %0, %struct.my_struct** %2, align 8
  call void @llvm.dbg.declare(metadata %struct.my_struct** %2, metadata !88, metadata !DIExpression()), !dbg !89
  %3 = load %struct.my_struct*, %struct.my_struct** %2, align 8, !dbg !90
  %4 = getelementptr inbounds %struct.my_struct, %struct.my_struct* %3, i32 0, i32 3, !dbg !92
  %5 = load double, double* %4, align 8, !dbg !92
  %6 = fcmp ogt double %5, 5.000000e-01, !dbg !93
  br i1 %6, label %7, label %12, !dbg !94

7:                                                ; preds = %1
  %8 = load %struct.my_struct*, %struct.my_struct** %2, align 8, !dbg !95
  %9 = getelementptr inbounds %struct.my_struct, %struct.my_struct* %8, i32 0, i32 0, !dbg !97
  %10 = load %struct.my_struct*, %struct.my_struct** %2, align 8, !dbg !98
  %11 = getelementptr inbounds %struct.my_struct, %struct.my_struct* %10, i32 0, i32 1, !dbg !99
  call void @swap_fields(i32* %9, i32* %11), !dbg !100
  br label %15, !dbg !101

12:                                               ; preds = %1
  %13 = load %struct.my_struct*, %struct.my_struct** %2, align 8, !dbg !102
  %14 = getelementptr inbounds %struct.my_struct, %struct.my_struct* %13, i32 0, i32 2, !dbg !104
  store i8 113, i8* %14, align 8, !dbg !105
  br label %15

15:                                               ; preds = %12, %7
  ret void, !dbg !106
}

attributes #0 = { noinline nounwind optnone uwtable "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { nofree nosync nounwind readnone speculatable willreturn }
attributes #2 = { nounwind "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #3 = { nounwind }

!llvm.dbg.cu = !{!0}
!llvm.ident = !{!16}
!llvm.module.flags = !{!17, !18, !19, !20, !21}

!0 = distinct !DICompileUnit(language: DW_LANG_C99, file: !1, producer: "clang version 13.0.0", isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug, enums: !2, retainedTypes: !3, splitDebugInlining: false, nameTableKind: None)
!1 = !DIFile(filename: "library.c", directory: "/workspaces/libfuzz/regression_tests/condition_extractor/intfuncinvok")
!2 = !{}
!3 = !{!4}
!4 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !5, size: 64)
!5 = !DIDerivedType(tag: DW_TAG_typedef, name: "my_struct", file: !6, line: 10, baseType: !7)
!6 = !DIFile(filename: "./library.h", directory: "/workspaces/libfuzz/regression_tests/condition_extractor/intfuncinvok")
!7 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "my_struct", file: !6, line: 5, size: 192, elements: !8)
!8 = !{!9, !11, !12, !14}
!9 = !DIDerivedType(tag: DW_TAG_member, name: "field_a", scope: !7, file: !6, line: 6, baseType: !10, size: 32)
!10 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!11 = !DIDerivedType(tag: DW_TAG_member, name: "field_b", scope: !7, file: !6, line: 7, baseType: !10, size: 32, offset: 32)
!12 = !DIDerivedType(tag: DW_TAG_member, name: "field_c", scope: !7, file: !6, line: 8, baseType: !13, size: 8, offset: 64)
!13 = !DIBasicType(name: "char", size: 8, encoding: DW_ATE_signed_char)
!14 = !DIDerivedType(tag: DW_TAG_member, name: "field_d", scope: !7, file: !6, line: 9, baseType: !15, size: 64, offset: 128)
!15 = !DIBasicType(name: "double", size: 64, encoding: DW_ATE_float)
!16 = !{!"clang version 13.0.0"}
!17 = !{i32 7, !"Dwarf Version", i32 4}
!18 = !{i32 2, !"Debug Info Version", i32 3}
!19 = !{i32 1, !"wchar_size", i32 4}
!20 = !{i32 7, !"uwtable", i32 1}
!21 = !{i32 7, !"frame-pointer", i32 2}
!22 = distinct !DISubprogram(name: "set_default", scope: !1, file: !1, line: 9, type: !23, scopeLine: 9, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !2)
!23 = !DISubroutineType(types: !24)
!24 = !{null, !4}
!25 = !DILocalVariable(name: "s", arg: 1, scope: !22, file: !1, line: 9, type: !4)
!26 = !DILocation(line: 9, column: 29, scope: !22)
!27 = !DILocation(line: 10, column: 4, scope: !22)
!28 = !DILocation(line: 10, column: 7, scope: !22)
!29 = !DILocation(line: 10, column: 15, scope: !22)
!30 = !DILocation(line: 11, column: 4, scope: !22)
!31 = !DILocation(line: 11, column: 7, scope: !22)
!32 = !DILocation(line: 11, column: 15, scope: !22)
!33 = !DILocation(line: 12, column: 4, scope: !22)
!34 = !DILocation(line: 12, column: 7, scope: !22)
!35 = !DILocation(line: 12, column: 15, scope: !22)
!36 = !DILocation(line: 13, column: 4, scope: !22)
!37 = !DILocation(line: 13, column: 7, scope: !22)
!38 = !DILocation(line: 13, column: 15, scope: !22)
!39 = !DILocation(line: 14, column: 1, scope: !22)
!40 = distinct !DISubprogram(name: "swap_fields", scope: !1, file: !1, line: 16, type: !41, scopeLine: 16, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !2)
!41 = !DISubroutineType(types: !42)
!42 = !{null, !43, !43}
!43 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !10, size: 64)
!44 = !DILocalVariable(name: "x1", arg: 1, scope: !40, file: !1, line: 16, type: !43)
!45 = !DILocation(line: 16, column: 23, scope: !40)
!46 = !DILocalVariable(name: "x2", arg: 2, scope: !40, file: !1, line: 16, type: !43)
!47 = !DILocation(line: 16, column: 32, scope: !40)
!48 = !DILocalVariable(name: "temp", scope: !40, file: !1, line: 17, type: !10)
!49 = !DILocation(line: 17, column: 8, scope: !40)
!50 = !DILocation(line: 17, column: 16, scope: !40)
!51 = !DILocation(line: 17, column: 15, scope: !40)
!52 = !DILocation(line: 18, column: 11, scope: !40)
!53 = !DILocation(line: 18, column: 10, scope: !40)
!54 = !DILocation(line: 18, column: 5, scope: !40)
!55 = !DILocation(line: 18, column: 8, scope: !40)
!56 = !DILocation(line: 19, column: 10, scope: !40)
!57 = !DILocation(line: 19, column: 5, scope: !40)
!58 = !DILocation(line: 19, column: 8, scope: !40)
!59 = !DILocation(line: 20, column: 1, scope: !40)
!60 = distinct !DISubprogram(name: "api1", scope: !1, file: !1, line: 22, type: !61, scopeLine: 22, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !2)
!61 = !DISubroutineType(types: !62)
!62 = !{!4, !10, !10, !13, !15, !63}
!63 = !DIBasicType(name: "short", size: 16, encoding: DW_ATE_signed)
!64 = !DILocalVariable(name: "a", arg: 1, scope: !60, file: !1, line: 22, type: !10)
!65 = !DILocation(line: 22, column: 21, scope: !60)
!66 = !DILocalVariable(name: "b", arg: 2, scope: !60, file: !1, line: 22, type: !10)
!67 = !DILocation(line: 22, column: 28, scope: !60)
!68 = !DILocalVariable(name: "c", arg: 3, scope: !60, file: !1, line: 22, type: !13)
!69 = !DILocation(line: 22, column: 36, scope: !60)
!70 = !DILocalVariable(name: "d", arg: 4, scope: !60, file: !1, line: 22, type: !15)
!71 = !DILocation(line: 22, column: 46, scope: !60)
!72 = !DILocalVariable(name: "f", arg: 5, scope: !60, file: !1, line: 22, type: !63)
!73 = !DILocation(line: 22, column: 55, scope: !60)
!74 = !DILocalVariable(name: "s", scope: !60, file: !1, line: 23, type: !4)
!75 = !DILocation(line: 23, column: 15, scope: !60)
!76 = !DILocation(line: 23, column: 31, scope: !60)
!77 = !DILocation(line: 23, column: 19, scope: !60)
!78 = !DILocation(line: 25, column: 8, scope: !79)
!79 = distinct !DILexicalBlock(scope: !60, file: !1, line: 25, column: 8)
!80 = !DILocation(line: 25, column: 8, scope: !60)
!81 = !DILocation(line: 26, column: 19, scope: !82)
!82 = distinct !DILexicalBlock(scope: !79, file: !1, line: 25, column: 11)
!83 = !DILocation(line: 26, column: 7, scope: !82)
!84 = !DILocation(line: 27, column: 4, scope: !82)
!85 = !DILocation(line: 34, column: 11, scope: !60)
!86 = !DILocation(line: 34, column: 4, scope: !60)
!87 = distinct !DISubprogram(name: "api2", scope: !1, file: !1, line: 37, type: !23, scopeLine: 37, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !2)
!88 = !DILocalVariable(name: "s", arg: 1, scope: !87, file: !1, line: 37, type: !4)
!89 = !DILocation(line: 37, column: 22, scope: !87)
!90 = !DILocation(line: 39, column: 8, scope: !91)
!91 = distinct !DILexicalBlock(scope: !87, file: !1, line: 39, column: 8)
!92 = !DILocation(line: 39, column: 11, scope: !91)
!93 = !DILocation(line: 39, column: 19, scope: !91)
!94 = !DILocation(line: 39, column: 8, scope: !87)
!95 = !DILocation(line: 40, column: 20, scope: !96)
!96 = distinct !DILexicalBlock(scope: !91, file: !1, line: 39, column: 26)
!97 = !DILocation(line: 40, column: 23, scope: !96)
!98 = !DILocation(line: 40, column: 33, scope: !96)
!99 = !DILocation(line: 40, column: 36, scope: !96)
!100 = !DILocation(line: 40, column: 7, scope: !96)
!101 = !DILocation(line: 41, column: 4, scope: !96)
!102 = !DILocation(line: 42, column: 7, scope: !103)
!103 = distinct !DILexicalBlock(scope: !91, file: !1, line: 41, column: 11)
!104 = !DILocation(line: 42, column: 10, scope: !103)
!105 = !DILocation(line: 42, column: 18, scope: !103)
!106 = !DILocation(line: 44, column: 1, scope: !87)
