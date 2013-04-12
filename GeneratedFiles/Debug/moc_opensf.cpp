/****************************************************************************
** Meta object code from reading C++ file 'opensf.h'
**
** Created: Thu Apr 11 22:16:44 2013
**      by: The Qt Meta Object Compiler version 63 (Qt 4.8.1)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../opensf.h"
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'opensf.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 63
#error "This file was generated using the moc from 4.8.1. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
static const uint qt_meta_data_OpenSF[] = {

 // content:
       6,       // revision
       0,       // classname
       0,    0, // classinfo
       3,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: signature, parameters, type, tag, flags
      20,   12,    8,    7, 0x0a,
      33,    7,    7,    7, 0x08,
      45,    7,    7,    7, 0x08,

       0        // eod
};

static const char qt_meta_stringdata_OpenSF[] = {
    "OpenSF\0\0int\0pkt_num\0display(int)\0"
    "start_cap()\0stop_cap()\0"
};

void OpenSF::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        Q_ASSERT(staticMetaObject.cast(_o));
        OpenSF *_t = static_cast<OpenSF *>(_o);
        switch (_id) {
        case 0: { int _r = _t->display((*reinterpret_cast< int(*)>(_a[1])));
            if (_a[0]) *reinterpret_cast< int*>(_a[0]) = _r; }  break;
        case 1: _t->start_cap(); break;
        case 2: _t->stop_cap(); break;
        default: ;
        }
    }
}

const QMetaObjectExtraData OpenSF::staticMetaObjectExtraData = {
    0,  qt_static_metacall 
};

const QMetaObject OpenSF::staticMetaObject = {
    { &QMainWindow::staticMetaObject, qt_meta_stringdata_OpenSF,
      qt_meta_data_OpenSF, &staticMetaObjectExtraData }
};

#ifdef Q_NO_DATA_RELOCATION
const QMetaObject &OpenSF::getStaticMetaObject() { return staticMetaObject; }
#endif //Q_NO_DATA_RELOCATION

const QMetaObject *OpenSF::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->metaObject : &staticMetaObject;
}

void *OpenSF::qt_metacast(const char *_clname)
{
    if (!_clname) return 0;
    if (!strcmp(_clname, qt_meta_stringdata_OpenSF))
        return static_cast<void*>(const_cast< OpenSF*>(this));
    return QMainWindow::qt_metacast(_clname);
}

int OpenSF::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QMainWindow::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 3)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 3;
    }
    return _id;
}
QT_END_MOC_NAMESPACE
