; ModuleID = 'library.o.bc'
source_filename = "llvm-link"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

%struct.my_struct = type { i8*, i64, i64, i64, i64, i64, i64, i64, i64, i64, i64 }

; Function Attrs: mustprogress nofree norecurse nosync nounwind uwtable willreturn writeonly
define dso_local void @another_init(%struct.my_struct* nocapture %0) local_unnamed_addr #0 !dbg !32 {
  call void @llvm.dbg.value(metadata %struct.my_struct* %0, metadata !36, metadata !DIExpression()), !dbg !37
  %2 = getelementptr inbounds %struct.my_struct, %struct.my_struct* %0, i64 0, i32 3, !dbg !38
  store i64 10, i64* %2, align 8, !dbg !39, !tbaa !40
  %3 = getelementptr inbounds %struct.my_struct, %struct.my_struct* %0, i64 0, i32 9, !dbg !46
  store i64 5, i64* %3, align 8, !dbg !47, !tbaa !48
  ret void, !dbg !49
}

; Function Attrs: nofree nosync nounwind readnone speculatable willreturn
declare void @llvm.dbg.value(metadata, metadata, metadata) #1

; Function Attrs: mustprogress nofree nounwind uwtable willreturn
define dso_local noalias %struct.my_struct* @my_malloc() local_unnamed_addr #2 !dbg !50 {
  %1 = tail call noalias align 16 dereferenceable_or_null(88) i8* @malloc(i64 88) #4, !dbg !52
  %2 = bitcast i8* %1 to %struct.my_struct*, !dbg !53
  ret %struct.my_struct* %2, !dbg !54
}

; Function Attrs: inaccessiblememonly mustprogress nofree nounwind willreturn
declare dso_local noalias noundef align 16 i8* @malloc(i64 noundef) local_unnamed_addr #3

; Function Attrs: mustprogress nofree nounwind uwtable willreturn
define dso_local noalias %struct.my_struct* @create_struct(i64 %0, i64 %1) local_unnamed_addr #2 !dbg !55 {
  call void @llvm.dbg.value(metadata i64 %0, metadata !59, metadata !DIExpression()), !dbg !62
  call void @llvm.dbg.value(metadata i64 %1, metadata !60, metadata !DIExpression()), !dbg !62
  %3 = icmp eq i64 %0, 0, !dbg !63
  %4 = icmp eq i64 %1, 1
  %5 = select i1 %3, i1 true, i1 %4, !dbg !65
  br i1 %5, label %11, label %6, !dbg !65

6:                                                ; preds = %2
  %7 = tail call noalias align 16 dereferenceable_or_null(88) i8* @malloc(i64 88) #4, !dbg !66
  %8 = bitcast i8* %7 to %struct.my_struct*, !dbg !68
  call void @llvm.dbg.value(metadata %struct.my_struct* %8, metadata !61, metadata !DIExpression()), !dbg !62
  %9 = getelementptr inbounds %struct.my_struct, %struct.my_struct* %8, i64 0, i32 1, !dbg !69
  store i64 %0, i64* %9, align 8, !dbg !70, !tbaa !71
  %10 = getelementptr inbounds %struct.my_struct, %struct.my_struct* %8, i64 0, i32 2, !dbg !72
  store i64 %1, i64* %10, align 16, !dbg !73, !tbaa !74
  br label %11

11:                                               ; preds = %2, %6
  %12 = phi %struct.my_struct* [ %8, %6 ], [ null, %2 ], !dbg !62
  ret %struct.my_struct* %12, !dbg !75
}

; Function Attrs: mustprogress nofree nounwind uwtable willreturn
define dso_local noalias %struct.my_struct* @create_default_struct() local_unnamed_addr #2 !dbg !76 {
  call void @llvm.dbg.value(metadata i64 10, metadata !59, metadata !DIExpression()) #4, !dbg !79
  call void @llvm.dbg.value(metadata i64 5, metadata !60, metadata !DIExpression()) #4, !dbg !79
  %1 = tail call noalias align 16 dereferenceable_or_null(88) i8* @malloc(i64 88) #4, !dbg !81
  %2 = bitcast i8* %1 to %struct.my_struct*, !dbg !83
  call void @llvm.dbg.value(metadata %struct.my_struct* %2, metadata !61, metadata !DIExpression()) #4, !dbg !79
  %3 = getelementptr inbounds %struct.my_struct, %struct.my_struct* %2, i64 0, i32 1, !dbg !84
  %4 = bitcast i64* %3 to <2 x i64>*, !dbg !85
  store <2 x i64> <i64 10, i64 5>, <2 x i64>* %4, align 8, !dbg !85, !tbaa !86
  call void @llvm.dbg.value(metadata %struct.my_struct* %2, metadata !78, metadata !DIExpression()), !dbg !87
  call void @llvm.dbg.value(metadata %struct.my_struct* %2, metadata !36, metadata !DIExpression()), !dbg !88
  %5 = getelementptr inbounds %struct.my_struct, %struct.my_struct* %2, i64 0, i32 3, !dbg !90
  store i64 10, i64* %5, align 8, !dbg !91, !tbaa !40
  %6 = getelementptr inbounds %struct.my_struct, %struct.my_struct* %2, i64 0, i32 9, !dbg !92
  store i64 5, i64* %6, align 8, !dbg !93, !tbaa !48
  ret %struct.my_struct* %2, !dbg !94
}

attributes #0 = { mustprogress nofree norecurse nosync nounwind uwtable willreturn writeonly "frame-pointer"="none" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { nofree nosync nounwind readnone speculatable willreturn }
attributes #2 = { mustprogress nofree nounwind uwtable willreturn "frame-pointer"="none" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #3 = { inaccessiblememonly mustprogress nofree nounwind willreturn "frame-pointer"="none" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #4 = { nounwind }

!llvm.dbg.cu = !{!0}
!llvm.ident = !{!27}
!llvm.module.flags = !{!28, !29, !30, !31}

!0 = distinct !DICompileUnit(language: DW_LANG_C99, file: !1, producer: "Ubuntu clang version 13.0.1-++20220120110924+75e33f71c2da-1~exp1~20220120231001.58", isOptimized: true, runtimeVersion: 0, emissionKind: FullDebug, enums: !2, retainedTypes: !3, splitDebugInlining: false, nameTableKind: None)
!1 = !DIFile(filename: "library.c", directory: "/workspace/libfuzz/tests/fieldsensitivetest")
!2 = !{}
!3 = !{!4}
!4 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !5, size: 64)
!5 = !DIDerivedType(tag: DW_TAG_typedef, name: "my_struct", file: !6, line: 38, baseType: !7)
!6 = !DIFile(filename: "./library.h", directory: "/workspace/libfuzz/tests/fieldsensitivetest")
!7 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "my_struct", file: !6, line: 10, size: 704, elements: !8)
!8 = !{!9, !12, !18, !19, !20, !21, !22, !23, !24, !25, !26}
!9 = !DIDerivedType(tag: DW_TAG_member, name: "c", scope: !7, file: !6, line: 12, baseType: !10, size: 64)
!10 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !11, size: 64)
!11 = !DIBasicType(name: "char", size: 8, encoding: DW_ATE_signed_char)
!12 = !DIDerivedType(tag: DW_TAG_member, name: "a", scope: !7, file: !6, line: 13, baseType: !13, size: 64, offset: 64)
!13 = !DIDerivedType(tag: DW_TAG_typedef, name: "uint64_t", file: !14, line: 27, baseType: !15)
!14 = !DIFile(filename: "/usr/include/x86_64-linux-gnu/bits/stdint-uintn.h", directory: "")
!15 = !DIDerivedType(tag: DW_TAG_typedef, name: "__uint64_t", file: !16, line: 45, baseType: !17)
!16 = !DIFile(filename: "/usr/include/x86_64-linux-gnu/bits/types.h", directory: "")
!17 = !DIBasicType(name: "long unsigned int", size: 64, encoding: DW_ATE_unsigned)
!18 = !DIDerivedType(tag: DW_TAG_member, name: "b", scope: !7, file: !6, line: 14, baseType: !13, size: 64, offset: 128)
!19 = !DIDerivedType(tag: DW_TAG_member, name: "cc", scope: !7, file: !6, line: 15, baseType: !13, size: 64, offset: 192)
!20 = !DIDerivedType(tag: DW_TAG_member, name: "d", scope: !7, file: !6, line: 16, baseType: !13, size: 64, offset: 256)
!21 = !DIDerivedType(tag: DW_TAG_member, name: "e", scope: !7, file: !6, line: 17, baseType: !13, size: 64, offset: 320)
!22 = !DIDerivedType(tag: DW_TAG_member, name: "f", scope: !7, file: !6, line: 18, baseType: !13, size: 64, offset: 384)
!23 = !DIDerivedType(tag: DW_TAG_member, name: "g", scope: !7, file: !6, line: 19, baseType: !13, size: 64, offset: 448)
!24 = !DIDerivedType(tag: DW_TAG_member, name: "h", scope: !7, file: !6, line: 20, baseType: !13, size: 64, offset: 512)
!25 = !DIDerivedType(tag: DW_TAG_member, name: "i", scope: !7, file: !6, line: 21, baseType: !13, size: 64, offset: 576)
!26 = !DIDerivedType(tag: DW_TAG_member, name: "l", scope: !7, file: !6, line: 22, baseType: !13, size: 64, offset: 640)
!27 = !{!"Ubuntu clang version 13.0.1-++20220120110924+75e33f71c2da-1~exp1~20220120231001.58"}
!28 = !{i32 7, !"Dwarf Version", i32 4}
!29 = !{i32 2, !"Debug Info Version", i32 3}
!30 = !{i32 1, !"wchar_size", i32 4}
!31 = !{i32 7, !"uwtable", i32 1}
!32 = distinct !DISubprogram(name: "another_init", scope: !1, file: !1, line: 9, type: !33, scopeLine: 9, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0, retainedNodes: !35)
!33 = !DISubroutineType(types: !34)
!34 = !{null, !4}
!35 = !{!36}
!36 = !DILocalVariable(name: "m", arg: 1, scope: !32, file: !1, line: 9, type: !4)
!37 = !DILocation(line: 0, scope: !32)
!38 = !DILocation(line: 10, column: 5, scope: !32)
!39 = !DILocation(line: 10, column: 8, scope: !32)
!40 = !{!41, !45, i64 24}
!41 = !{!"my_struct", !42, i64 0, !45, i64 8, !45, i64 16, !45, i64 24, !45, i64 32, !45, i64 40, !45, i64 48, !45, i64 56, !45, i64 64, !45, i64 72, !45, i64 80}
!42 = !{!"any pointer", !43, i64 0}
!43 = !{!"omnipotent char", !44, i64 0}
!44 = !{!"Simple C/C++ TBAA"}
!45 = !{!"long", !43, i64 0}
!46 = !DILocation(line: 11, column: 5, scope: !32)
!47 = !DILocation(line: 11, column: 7, scope: !32)
!48 = !{!41, !45, i64 72}
!49 = !DILocation(line: 12, column: 1, scope: !32)
!50 = distinct !DISubprogram(name: "my_malloc", scope: !1, file: !1, line: 14, type: !51, scopeLine: 14, flags: DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0, retainedNodes: !2)
!51 = !DISubroutineType(types: !3)
!52 = !DILocation(line: 15, column: 21, scope: !50)
!53 = !DILocation(line: 15, column: 9, scope: !50)
!54 = !DILocation(line: 15, column: 2, scope: !50)
!55 = distinct !DISubprogram(name: "create_struct", scope: !1, file: !1, line: 18, type: !56, scopeLine: 18, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0, retainedNodes: !58)
!56 = !DISubroutineType(types: !57)
!57 = !{!4, !13, !13}
!58 = !{!59, !60, !61}
!59 = !DILocalVariable(name: "aa", arg: 1, scope: !55, file: !1, line: 18, type: !13)
!60 = !DILocalVariable(name: "bb", arg: 2, scope: !55, file: !1, line: 18, type: !13)
!61 = !DILocalVariable(name: "m", scope: !55, file: !1, line: 23, type: !4)
!62 = !DILocation(line: 0, scope: !55)
!63 = !DILocation(line: 20, column: 9, scope: !64)
!64 = distinct !DILexicalBlock(scope: !55, file: !1, line: 20, column: 6)
!65 = !DILocation(line: 20, column: 14, scope: !64)
!66 = !DILocation(line: 15, column: 21, scope: !50, inlinedAt: !67)
!67 = distinct !DILocation(line: 23, column: 17, scope: !55)
!68 = !DILocation(line: 15, column: 9, scope: !50, inlinedAt: !67)
!69 = !DILocation(line: 25, column: 5, scope: !55)
!70 = !DILocation(line: 25, column: 7, scope: !55)
!71 = !{!41, !45, i64 8}
!72 = !DILocation(line: 26, column: 5, scope: !55)
!73 = !DILocation(line: 26, column: 7, scope: !55)
!74 = !{!41, !45, i64 16}
!75 = !DILocation(line: 30, column: 1, scope: !55)
!76 = distinct !DISubprogram(name: "create_default_struct", scope: !1, file: !1, line: 32, type: !51, scopeLine: 32, flags: DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !0, retainedNodes: !77)
!77 = !{!78}
!78 = !DILocalVariable(name: "m", scope: !76, file: !1, line: 34, type: !4)
!79 = !DILocation(line: 0, scope: !55, inlinedAt: !80)
!80 = distinct !DILocation(line: 34, column: 17, scope: !76)
!81 = !DILocation(line: 15, column: 21, scope: !50, inlinedAt: !82)
!82 = distinct !DILocation(line: 23, column: 17, scope: !55, inlinedAt: !80)
!83 = !DILocation(line: 15, column: 9, scope: !50, inlinedAt: !82)
!84 = !DILocation(line: 25, column: 5, scope: !55, inlinedAt: !80)
!85 = !DILocation(line: 25, column: 7, scope: !55, inlinedAt: !80)
!86 = !{!45, !45, i64 0}
!87 = !DILocation(line: 0, scope: !76)
!88 = !DILocation(line: 0, scope: !32, inlinedAt: !89)
!89 = distinct !DILocation(line: 36, column: 2, scope: !76)
!90 = !DILocation(line: 10, column: 5, scope: !32, inlinedAt: !89)
!91 = !DILocation(line: 10, column: 8, scope: !32, inlinedAt: !89)
!92 = !DILocation(line: 11, column: 5, scope: !32, inlinedAt: !89)
!93 = !DILocation(line: 11, column: 7, scope: !32, inlinedAt: !89)
!94 = !DILocation(line: 38, column: 2, scope: !76)
