; ModuleID = 'library.o.bc'
source_filename = "llvm-link"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

%struct.my_struct = type { i32, i32, i8, double }

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @set_default(%struct.my_struct* %s) #0 !dbg !20 {
entry:
  %s.addr = alloca %struct.my_struct*, align 8
  store %struct.my_struct* %s, %struct.my_struct** %s.addr, align 8
  call void @llvm.dbg.declare(metadata %struct.my_struct** %s.addr, metadata !23, metadata !DIExpression()), !dbg !24
  %0 = load %struct.my_struct*, %struct.my_struct** %s.addr, align 8, !dbg !25
  %field_a = getelementptr inbounds %struct.my_struct, %struct.my_struct* %0, i32 0, i32 0, !dbg !26
  store i32 4, i32* %field_a, align 8, !dbg !27
  %1 = load %struct.my_struct*, %struct.my_struct** %s.addr, align 8, !dbg !28
  %field_b = getelementptr inbounds %struct.my_struct, %struct.my_struct* %1, i32 0, i32 1, !dbg !29
  store i32 8, i32* %field_b, align 4, !dbg !30
  %2 = load %struct.my_struct*, %struct.my_struct** %s.addr, align 8, !dbg !31
  %field_c = getelementptr inbounds %struct.my_struct, %struct.my_struct* %2, i32 0, i32 2, !dbg !32
  store i8 88, i8* %field_c, align 8, !dbg !33
  %3 = load %struct.my_struct*, %struct.my_struct** %s.addr, align 8, !dbg !34
  %field_d = getelementptr inbounds %struct.my_struct, %struct.my_struct* %3, i32 0, i32 3, !dbg !35
  store double 1.230000e+01, double* %field_d, align 8, !dbg !36
  ret void, !dbg !37
}

; Function Attrs: nofree nosync nounwind readnone speculatable willreturn
declare void @llvm.dbg.declare(metadata, metadata, metadata) #1

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @swap_fields(i32* %x1, i32* %x2) #0 !dbg !38 {
entry:
  %x1.addr = alloca i32*, align 8
  %x2.addr = alloca i32*, align 8
  %temp = alloca i32, align 4
  store i32* %x1, i32** %x1.addr, align 8
  call void @llvm.dbg.declare(metadata i32** %x1.addr, metadata !42, metadata !DIExpression()), !dbg !43
  store i32* %x2, i32** %x2.addr, align 8
  call void @llvm.dbg.declare(metadata i32** %x2.addr, metadata !44, metadata !DIExpression()), !dbg !45
  call void @llvm.dbg.declare(metadata i32* %temp, metadata !46, metadata !DIExpression()), !dbg !47
  %0 = load i32*, i32** %x1.addr, align 8, !dbg !48
  %1 = load i32, i32* %0, align 4, !dbg !49
  store i32 %1, i32* %temp, align 4, !dbg !47
  %2 = load i32*, i32** %x2.addr, align 8, !dbg !50
  %3 = load i32, i32* %2, align 4, !dbg !51
  %4 = load i32*, i32** %x1.addr, align 8, !dbg !52
  store i32 %3, i32* %4, align 4, !dbg !53
  %5 = load i32, i32* %temp, align 4, !dbg !54
  %6 = load i32*, i32** %x2.addr, align 8, !dbg !55
  store i32 %5, i32* %6, align 4, !dbg !56
  ret void, !dbg !57
}

; Function Attrs: noinline nounwind optnone uwtable
define dso_local %struct.my_struct* @api1(i32 %a, i32 %b, i8 signext %c, double %d, i16 signext %f) #0 !dbg !58 {
entry:
  %a.addr = alloca i32, align 4
  %b.addr = alloca i32, align 4
  %c.addr = alloca i8, align 1
  %d.addr = alloca double, align 8
  %f.addr = alloca i16, align 2
  %s = alloca %struct.my_struct*, align 8
  store i32 %a, i32* %a.addr, align 4
  call void @llvm.dbg.declare(metadata i32* %a.addr, metadata !62, metadata !DIExpression()), !dbg !63
  store i32 %b, i32* %b.addr, align 4
  call void @llvm.dbg.declare(metadata i32* %b.addr, metadata !64, metadata !DIExpression()), !dbg !65
  store i8 %c, i8* %c.addr, align 1
  call void @llvm.dbg.declare(metadata i8* %c.addr, metadata !66, metadata !DIExpression()), !dbg !67
  store double %d, double* %d.addr, align 8
  call void @llvm.dbg.declare(metadata double* %d.addr, metadata !68, metadata !DIExpression()), !dbg !69
  store i16 %f, i16* %f.addr, align 2
  call void @llvm.dbg.declare(metadata i16* %f.addr, metadata !70, metadata !DIExpression()), !dbg !71
  call void @llvm.dbg.declare(metadata %struct.my_struct** %s, metadata !72, metadata !DIExpression()), !dbg !73
  %call = call noalias i8* @malloc(i64 24) #3, !dbg !74
  %0 = bitcast i8* %call to %struct.my_struct*, !dbg !75
  store %struct.my_struct* %0, %struct.my_struct** %s, align 8, !dbg !73
  %1 = load i16, i16* %f.addr, align 2, !dbg !76
  %tobool = icmp ne i16 %1, 0, !dbg !76
  br i1 %tobool, label %if.then, label %if.end, !dbg !78

if.then:                                          ; preds = %entry
  %2 = load %struct.my_struct*, %struct.my_struct** %s, align 8, !dbg !79
  call void @set_default(%struct.my_struct* %2), !dbg !81
  br label %if.end, !dbg !82

if.end:                                           ; preds = %if.then, %entry
  %3 = load %struct.my_struct*, %struct.my_struct** %s, align 8, !dbg !83
  ret %struct.my_struct* %3, !dbg !84
}

; Function Attrs: nounwind
declare dso_local noalias i8* @malloc(i64) #2

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @api2(%struct.my_struct* %s) #0 !dbg !85 {
entry:
  %s.addr = alloca %struct.my_struct*, align 8
  store %struct.my_struct* %s, %struct.my_struct** %s.addr, align 8
  call void @llvm.dbg.declare(metadata %struct.my_struct** %s.addr, metadata !86, metadata !DIExpression()), !dbg !87
  %0 = load %struct.my_struct*, %struct.my_struct** %s.addr, align 8, !dbg !88
  %field_d = getelementptr inbounds %struct.my_struct, %struct.my_struct* %0, i32 0, i32 3, !dbg !90
  %1 = load double, double* %field_d, align 8, !dbg !90
  %cmp = fcmp ogt double %1, 5.000000e-01, !dbg !91
  br i1 %cmp, label %if.then, label %if.else, !dbg !92

if.then:                                          ; preds = %entry
  %2 = load %struct.my_struct*, %struct.my_struct** %s.addr, align 8, !dbg !93
  %field_a = getelementptr inbounds %struct.my_struct, %struct.my_struct* %2, i32 0, i32 0, !dbg !95
  %3 = load %struct.my_struct*, %struct.my_struct** %s.addr, align 8, !dbg !96
  %field_b = getelementptr inbounds %struct.my_struct, %struct.my_struct* %3, i32 0, i32 1, !dbg !97
  call void @swap_fields(i32* %field_a, i32* %field_b), !dbg !98
  br label %if.end, !dbg !99

if.else:                                          ; preds = %entry
  %4 = load %struct.my_struct*, %struct.my_struct** %s.addr, align 8, !dbg !100
  %field_c = getelementptr inbounds %struct.my_struct, %struct.my_struct* %4, i32 0, i32 2, !dbg !102
  store i8 113, i8* %field_c, align 8, !dbg !103
  br label %if.end

if.end:                                           ; preds = %if.else, %if.then
  ret void, !dbg !104
}

attributes #0 = { noinline nounwind optnone uwtable "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "min-legal-vector-width"="0" "no-infs-fp-math"="false" "no-jump-tables"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #1 = { nofree nosync nounwind readnone speculatable willreturn }
attributes #2 = { nounwind "disable-tail-calls"="false" "frame-pointer"="all" "less-precise-fpmad"="false" "no-infs-fp-math"="false" "no-nans-fp-math"="false" "no-signed-zeros-fp-math"="false" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" "unsafe-fp-math"="false" "use-soft-float"="false" }
attributes #3 = { nounwind }

!llvm.dbg.cu = !{!0}
!llvm.ident = !{!16}
!llvm.module.flags = !{!17, !18, !19}

!0 = distinct !DICompileUnit(language: DW_LANG_C99, file: !1, producer: "clang version 12.0.0", isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug, enums: !2, retainedTypes: !3, splitDebugInlining: false, nameTableKind: None)
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
!16 = !{!"clang version 12.0.0"}
!17 = !{i32 7, !"Dwarf Version", i32 4}
!18 = !{i32 2, !"Debug Info Version", i32 3}
!19 = !{i32 1, !"wchar_size", i32 4}
!20 = distinct !DISubprogram(name: "set_default", scope: !1, file: !1, line: 9, type: !21, scopeLine: 9, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !2)
!21 = !DISubroutineType(types: !22)
!22 = !{null, !4}
!23 = !DILocalVariable(name: "s", arg: 1, scope: !20, file: !1, line: 9, type: !4)
!24 = !DILocation(line: 9, column: 29, scope: !20)
!25 = !DILocation(line: 10, column: 4, scope: !20)
!26 = !DILocation(line: 10, column: 7, scope: !20)
!27 = !DILocation(line: 10, column: 15, scope: !20)
!28 = !DILocation(line: 11, column: 4, scope: !20)
!29 = !DILocation(line: 11, column: 7, scope: !20)
!30 = !DILocation(line: 11, column: 15, scope: !20)
!31 = !DILocation(line: 12, column: 4, scope: !20)
!32 = !DILocation(line: 12, column: 7, scope: !20)
!33 = !DILocation(line: 12, column: 15, scope: !20)
!34 = !DILocation(line: 13, column: 4, scope: !20)
!35 = !DILocation(line: 13, column: 7, scope: !20)
!36 = !DILocation(line: 13, column: 15, scope: !20)
!37 = !DILocation(line: 14, column: 1, scope: !20)
!38 = distinct !DISubprogram(name: "swap_fields", scope: !1, file: !1, line: 16, type: !39, scopeLine: 16, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !2)
!39 = !DISubroutineType(types: !40)
!40 = !{null, !41, !41}
!41 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !10, size: 64)
!42 = !DILocalVariable(name: "x1", arg: 1, scope: !38, file: !1, line: 16, type: !41)
!43 = !DILocation(line: 16, column: 23, scope: !38)
!44 = !DILocalVariable(name: "x2", arg: 2, scope: !38, file: !1, line: 16, type: !41)
!45 = !DILocation(line: 16, column: 32, scope: !38)
!46 = !DILocalVariable(name: "temp", scope: !38, file: !1, line: 17, type: !10)
!47 = !DILocation(line: 17, column: 8, scope: !38)
!48 = !DILocation(line: 17, column: 16, scope: !38)
!49 = !DILocation(line: 17, column: 15, scope: !38)
!50 = !DILocation(line: 18, column: 11, scope: !38)
!51 = !DILocation(line: 18, column: 10, scope: !38)
!52 = !DILocation(line: 18, column: 5, scope: !38)
!53 = !DILocation(line: 18, column: 8, scope: !38)
!54 = !DILocation(line: 19, column: 10, scope: !38)
!55 = !DILocation(line: 19, column: 5, scope: !38)
!56 = !DILocation(line: 19, column: 8, scope: !38)
!57 = !DILocation(line: 20, column: 1, scope: !38)
!58 = distinct !DISubprogram(name: "api1", scope: !1, file: !1, line: 22, type: !59, scopeLine: 22, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !2)
!59 = !DISubroutineType(types: !60)
!60 = !{!4, !10, !10, !13, !15, !61}
!61 = !DIBasicType(name: "short", size: 16, encoding: DW_ATE_signed)
!62 = !DILocalVariable(name: "a", arg: 1, scope: !58, file: !1, line: 22, type: !10)
!63 = !DILocation(line: 22, column: 21, scope: !58)
!64 = !DILocalVariable(name: "b", arg: 2, scope: !58, file: !1, line: 22, type: !10)
!65 = !DILocation(line: 22, column: 28, scope: !58)
!66 = !DILocalVariable(name: "c", arg: 3, scope: !58, file: !1, line: 22, type: !13)
!67 = !DILocation(line: 22, column: 36, scope: !58)
!68 = !DILocalVariable(name: "d", arg: 4, scope: !58, file: !1, line: 22, type: !15)
!69 = !DILocation(line: 22, column: 46, scope: !58)
!70 = !DILocalVariable(name: "f", arg: 5, scope: !58, file: !1, line: 22, type: !61)
!71 = !DILocation(line: 22, column: 55, scope: !58)
!72 = !DILocalVariable(name: "s", scope: !58, file: !1, line: 23, type: !4)
!73 = !DILocation(line: 23, column: 15, scope: !58)
!74 = !DILocation(line: 23, column: 31, scope: !58)
!75 = !DILocation(line: 23, column: 19, scope: !58)
!76 = !DILocation(line: 25, column: 8, scope: !77)
!77 = distinct !DILexicalBlock(scope: !58, file: !1, line: 25, column: 8)
!78 = !DILocation(line: 25, column: 8, scope: !58)
!79 = !DILocation(line: 26, column: 19, scope: !80)
!80 = distinct !DILexicalBlock(scope: !77, file: !1, line: 25, column: 11)
!81 = !DILocation(line: 26, column: 7, scope: !80)
!82 = !DILocation(line: 27, column: 4, scope: !80)
!83 = !DILocation(line: 34, column: 11, scope: !58)
!84 = !DILocation(line: 34, column: 4, scope: !58)
!85 = distinct !DISubprogram(name: "api2", scope: !1, file: !1, line: 37, type: !21, scopeLine: 37, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !2)
!86 = !DILocalVariable(name: "s", arg: 1, scope: !85, file: !1, line: 37, type: !4)
!87 = !DILocation(line: 37, column: 22, scope: !85)
!88 = !DILocation(line: 39, column: 8, scope: !89)
!89 = distinct !DILexicalBlock(scope: !85, file: !1, line: 39, column: 8)
!90 = !DILocation(line: 39, column: 11, scope: !89)
!91 = !DILocation(line: 39, column: 19, scope: !89)
!92 = !DILocation(line: 39, column: 8, scope: !85)
!93 = !DILocation(line: 40, column: 20, scope: !94)
!94 = distinct !DILexicalBlock(scope: !89, file: !1, line: 39, column: 26)
!95 = !DILocation(line: 40, column: 23, scope: !94)
!96 = !DILocation(line: 40, column: 33, scope: !94)
!97 = !DILocation(line: 40, column: 36, scope: !94)
!98 = !DILocation(line: 40, column: 7, scope: !94)
!99 = !DILocation(line: 41, column: 4, scope: !94)
!100 = !DILocation(line: 42, column: 7, scope: !101)
!101 = distinct !DILexicalBlock(scope: !89, file: !1, line: 41, column: 11)
!102 = !DILocation(line: 42, column: 10, scope: !101)
!103 = !DILocation(line: 42, column: 18, scope: !101)
!104 = !DILocation(line: 44, column: 1, scope: !85)
